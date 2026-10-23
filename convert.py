#!/usr/bin/env python3
"""Convert free-node feeds (vmess/trojan/ss only) into a curated Surge sub.

Pipeline: fetch the pre-split feeds -> convert to Surge lines (deduped on
the full config body) -> keep only nodes whose original remark identifies
an Asian region (mainland China excluded; unidentified remarks dropped) ->
connectivity-test every candidate (TCP connect; trojan and tls-vmess must
also finish a TLS handshake) -> keep the fastest by connect latency, at
most MAX_SELECT nodes. If fewer than MIN_SELECT Asian nodes pass, the
fastest tested non-Asian nodes top the list up to MIN_SELECT.

Output: surge-nodes.conf in the current directory, header comments record
generation time (UTC), the filter policy, per-source selected counts,
region counts and the test pass rate. Standard library only. The script
exits non-zero when the final selection is empty, so an empty
subscription is never published.
"""
import asyncio
import base64
import ipaddress
import json
import os
import re
import socket
import ssl
import statistics
import sys
import time
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone

# (source label, protocol, url, local filename for offline testing)
FEEDS = [
    ('Epodonios/v2ray-configs', 'vmess',
     'https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vmess.txt',
     'epodonios-vmess.txt'),
    ('Epodonios/v2ray-configs', 'trojan',
     'https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/trojan.txt',
     'epodonios-trojan.txt'),
    ('Epodonios/v2ray-configs', 'ss',
     'https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/ss.txt',
     'epodonios-ss.txt'),
    ('MustafaBaqer/VestraNet-Nodes', 'vmess',
     'https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/main/protocols/vmess.txt',
     'vestranet-vmess.txt'),
    ('MustafaBaqer/VestraNet-Nodes', 'trojan',
     'https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/main/protocols/trojan.txt',
     'vestranet-trojan.txt'),
    ('MustafaBaqer/VestraNet-Nodes', 'ss',
     'https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/main/protocols/shadowsocks.txt',
     'vestranet-ss.txt'),
]

MAX_SELECT = 200        # hard cap on published nodes
MIN_SELECT = 30         # top up with non-Asian nodes if Asia passes fewer
FALLBACK_POOL = 800     # max non-Asian nodes to test for the top-up
CONNECT_TIMEOUT = 3.0   # seconds, per attempt
TEST_DEADLINE = 540     # seconds, whole test phase
CONCURRENCY = 64


def b64d(s):
    s = s.strip().replace('-', '+').replace('_', '/')
    return base64.b64decode(s + '=' * (-len(s) % 4)).decode('utf-8', 'replace')


def split_lines(raw):
    raw = raw.strip()
    # Some feeds ship as one whole-file base64 blob; decode to a URI list.
    if raw and '://' not in raw.split('\n')[0][:32] and len(raw) > 100:
        try:
            raw = b64d(raw)
        except Exception:
            pass
    return [l.strip() for l in raw.splitlines() if l.strip() and '://' in l]


def fetch(url, local_name):
    local_dir = os.environ.get('SURGE_FEEDS_DIR')
    if local_dir:
        with open(os.path.join(local_dir, local_name), encoding='utf-8',
                  errors='replace') as f:
            return f.read()
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    return urllib.request.urlopen(req, timeout=90).read().decode('utf-8', 'replace')


def clean_name(src, proto, i):
    n = urllib.parse.unquote(src or '')
    n = ''.join(c if c not in ',=\r\n' else '_' for c in n)
    n = n.strip()[:48] or f'{proto}-{i}'
    return n


_seen_names = set()


def uniq(name):
    base, k = name, 2
    while name in _seen_names:
        name = f'{base}_{k}'
        k += 1
    _seen_names.add(name)
    return name


def frag_name(line):
    return line.rsplit('#', 1)[1] if '#' in line else ''


# ---------------- region detection (on the ORIGINAL remark) ----------------

ASIA_REGIONS = {'HK', 'TW', 'JP', 'SG', 'KR', 'MY', 'TH', 'VN', 'ID', 'PH',
                'IN', 'MO', 'KH', 'LA', 'MM', 'BD', 'PK', 'NP', 'LK', 'BN',
                'MN'}

# CN is scanned first so e.g. place names inside China win over the
# generic Asia keywords; keyword match is a plain substring scan.
_REGION_KEYWORDS = [
    ('CN', ('china', '中国', '中國', '大陆', '大陸', '内蒙古', '內蒙古',
            'beijing', 'shanghai', 'shenzhen', 'guangzhou', 'chengdu',
            '北京', '上海', '深圳', '广州', '廣州', '成都')),
    ('HK', ('hong kong', 'hongkong', '香港')),
    ('TW', ('taiwan', 'taipei', '台湾', '台灣', '台北')),
    ('JP', ('japan', 'tokyo', 'osaka', '日本', '东京', '東京', '大阪')),
    ('SG', ('singapore', '新加坡')),
    ('KR', ('korea', 'seoul', '韩国', '韓國', '首尔', '首爾')),
    ('MY', ('malaysia', '马来西亚', '馬來西亞')),
    ('TH', ('thailand', 'bangkok', '泰国', '泰國', '曼谷')),
    ('VN', ('vietnam', '越南')),
    ('ID', ('indonesia', 'jakarta', '印尼')),
    ('PH', ('philippines', '菲律宾', '菲律賓')),
    ('IN', ('india', '印度')),
    ('MO', ('macau', 'macao', '澳门', '澳門')),
    ('KH', ('cambodia', '柬埔寨')),
    ('LA', ('laos', '老挝', '老撾')),
    ('MM', ('myanmar', '缅甸', '緬甸')),
    ('BD', ('bangladesh', '孟加拉')),
    ('PK', ('pakistan', '巴基斯坦')),
    ('NP', ('nepal', '尼泊尔', '尼泊爾')),
    ('LK', ('sri lanka', '斯里兰卡')),
    ('BN', ('brunei', '文莱', '汶萊')),
    ('MN', ('mongolia', '蒙古')),
]

_TOKEN_ORDER = ['CN', 'HK', 'TW', 'JP', 'SG', 'KR', 'MY', 'TH', 'VN', 'ID',
                'PH', 'IN', 'MO']
_TOKEN_RES = {c: re.compile(r'(?<![A-Za-z])' + c + r'(?![A-Za-z])')
              for c in _TOKEN_ORDER}


def _flag_codes(text):
    """Country codes from flag emoji (regional-indicator pairs) in text."""
    codes, run = [], []
    for ch in text:
        o = ord(ch)
        if 0x1F1E6 <= o <= 0x1F1FF:
            run.append(o - 0x1F1E6)
            if len(run) == 2:
                codes.append(chr(65 + run[0]) + chr(65 + run[1]))
                run = []
        else:
            run = []
    return codes


def detect_region(remark):
    """Region code from a node's original remark, or None if unknown."""
    if not remark:
        return None
    text = urllib.parse.unquote(str(remark))
    flags = _flag_codes(text)
    if flags:
        return flags[0]
    low = text.lower()
    for code, kws in _REGION_KEYWORDS:
        if any(k in low for k in kws):
            return code
    # 'CN2' is a route product name, not China; blank it before token scan.
    upper = text.upper().replace('CN2', ' ')
    for code in _TOKEN_ORDER:
        if _TOKEN_RES[code].search(upper):
            return code
    return None


# ---------------- converters: return (surge line, meta) ----------------
# meta carries what curation needs later: host/port for the connect test,
# tls+sni for the handshake gate, and the ORIGINAL remark for region ID.

def conv_vmess(line, idx):
    cfg = json.loads(b64d(line[len('vmess://'):]))
    host, port = cfg.get('add'), cfg.get('port')
    if not host or not port:
        return None
    name = uniq(clean_name(cfg.get('ps', ''), 'vmess', idx))
    parts = [f'{name} = vmess', str(host), str(port),
             f"username={cfg.get('id', '')}"]
    if cfg.get('tls') == 'tls':
        parts.append('tls=true')
        if cfg.get('sni'):
            parts.append(f"sni={cfg['sni']}")
        elif cfg.get('host'):
            parts.append(f"sni={cfg['host']}")
    if cfg.get('net') == 'ws':
        parts.append('ws=true')
        if cfg.get('path'):
            parts.append(f"ws-path={cfg['path']}")
        if cfg.get('host'):
            parts.append(f"ws-headers=Host:{cfg['host']}")
    meta = {'host': str(host), 'port': int(port),
            'tls': cfg.get('tls') == 'tls',
            'sni': cfg.get('sni') or cfg.get('host') or '',
            'remark': cfg.get('ps', '') or ''}
    return ', '.join(parts), meta


def conv_trojan(line, idx):
    p = urllib.parse.urlparse(line)
    if not p.hostname or not p.port:
        return None
    raw_frag = frag_name(line)
    name = uniq(clean_name(raw_frag, 'trojan', idx))
    q = urllib.parse.parse_qs(p.query)
    sni = q.get('sni', [p.hostname])[0]
    parts = [f'{name} = trojan', p.hostname, str(p.port),
             f"password={urllib.parse.unquote(p.username or '')}", 'tls=true']
    parts.append(f'sni={sni}')
    meta = {'host': p.hostname, 'port': int(p.port), 'tls': True,
            'sni': sni, 'remark': urllib.parse.unquote(raw_frag)}
    return ', '.join(parts), meta


def conv_ss(line, idx):
    body = line[len('ss://'):]
    if '#' in body:
        body = body.split('#', 1)[0]
    if '@' in body:
        cred, hp = body.rsplit('@', 1)
        try:
            cred = b64d(cred)
        except Exception:
            pass
        method, _, pw = cred.partition(':')
    else:
        dec = b64d(body)
        method, _, rest = dec.partition(':')
        pw, _, hp = rest.partition('@')
    hp = hp.strip()
    if ':' not in hp or not method or not pw:
        return None
    host, _, port = hp.rpartition(':')
    if not host or not port.isdigit():
        return None
    raw_frag = frag_name(line)
    name = uniq(clean_name(raw_frag, 'ss', idx))
    meta = {'host': host, 'port': int(port), 'tls': False, 'sni': '',
            'remark': urllib.parse.unquote(raw_frag)}
    return ', '.join([f'{name} = ss', host, port,
                      f'encrypt-method={method}', f'password={pw}']), meta


CONV = {'vmess': conv_vmess, 'trojan': conv_trojan, 'ss': conv_ss}


# ---------------- connectivity testing ----------------

_TLS_CTX = ssl.create_default_context()
_TLS_CTX.check_hostname = False
_TLS_CTX.verify_mode = ssl.CERT_NONE


def _is_ip(h):
    try:
        ipaddress.ip_address(h)
        return True
    except Exception:
        return False


async def _try_once(rec):
    """One test attempt; returns TCP connect latency in ms, or None."""
    host, port = rec['host'], rec['port']
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, port, type=socket.SOCK_STREAM),
            timeout=CONNECT_TIMEOUT)
    except Exception:
        return None
    if not infos:
        return None
    writer = None
    latency = None
    ip = None
    for info in infos[:3]:
        ip = info[4][0]
        t0 = time.perf_counter()
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=CONNECT_TIMEOUT)
            latency = (time.perf_counter() - t0) * 1000.0
            break
        except Exception:
            writer, latency = None, None
    if writer is None:
        return None
    try:
        writer.close()
    except Exception:
        pass
    if rec['tls']:
        # Trojan / tls-vmess must also complete a real TLS handshake,
        # on a fresh connection to the same IP with the node's SNI.
        sni = rec['sni'] or ('' if _is_ip(host) else host)
        try:
            _, w2 = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=_TLS_CTX,
                                        server_hostname=sni or None),
                timeout=CONNECT_TIMEOUT)
            w2.close()
        except Exception:
            return None
    return latency


async def _test_rec(rec, sem):
    async with sem:
        for _ in range(2):  # up to 2 attempts, first success wins
            lat = await _try_once(rec)
            if lat is not None:
                rec['latency'] = lat
                return rec
        return None


async def run_tests(records):
    if not records:
        return []
    sem = asyncio.Semaphore(CONCURRENCY)
    tasks = [asyncio.ensure_future(_test_rec(r, sem)) for r in records]
    done, pending = await asyncio.wait(tasks, timeout=TEST_DEADLINE)
    for t in pending:
        t.cancel()
    out = []
    for t in done:
        if t.cancelled() or t.exception() is not None:
            continue
        if t.result() is not None:
            out.append(t.result())
    return out


# ---------------- main ----------------

def main():
    records = []
    seen_body = set()
    feed_counts = []          # (source label, proto, converted count)
    idx = 0
    for src, proto, url, local_name in FEEDS:
        ok = 0
        try:
            lines = split_lines(fetch(url, local_name))
        except Exception as e:
            print(f'WARN: fetch failed for {src}/{proto}: {e}', file=sys.stderr)
            lines = []
        for line in lines:
            if not line.startswith(proto + '://'):
                continue  # e.g. ssr:// lines inside an ss feed
            idx += 1
            try:
                res = CONV[proto](line, idx)
            except Exception:
                res = None
            if not res:
                continue
            pl, meta = res
            body = pl.split(' = ', 1)[1]  # dedupe on full config, keep 1st
            if body in seen_body:
                continue
            seen_body.add(body)
            meta.update(src=src, proto=proto, line=pl,
                        name=pl.split(' = ', 1)[0],
                        region=detect_region(meta['remark']))
            records.append(meta)
            ok += 1
        feed_counts.append((src, proto, ok))
        print(f'{src} {proto}: {ok} converted')

    print(f'records after conversion+dedupe: {len(records)}')
    asia = [r for r in records if r['region'] in ASIA_REGIONS]
    others = [r for r in records if r['region'] not in ASIA_REGIONS]
    print(f'asia candidates: {len(asia)} '
          f'(regions: {dict(Counter(r["region"] for r in asia))})')

    passed = asyncio.run(run_tests(asia)) if asia else []
    passed.sort(key=lambda r: r['latency'])
    if passed:
        lats = [r['latency'] for r in passed]
        print(f'asia tested passed: {len(passed)}; latency ms '
              f'min={min(lats):.0f} median={statistics.median(lats):.0f} '
              f'max={max(lats):.0f}')
    selected = passed[:MAX_SELECT]

    fallback_used = 0
    if len(selected) < MIN_SELECT:
        pool = others[:FALLBACK_POOL]
        print(f'asia passed < {MIN_SELECT}; testing {len(pool)} '
              f'non-asia fallback candidates')
        fb = asyncio.run(run_tests(pool)) if pool else []
        fb.sort(key=lambda r: r['latency'])
        add = fb[:MIN_SELECT - len(selected)]
        fallback_used = len(add)
        selected = selected + add
        print(f'fallback added: {fallback_used}')

    total = len(selected)
    print(f'selected total: {total}')
    if total == 0:
        print('ERROR: 0 nodes survived curation; not writing output',
              file=sys.stderr)
        return 1

    sel_by_src = Counter(r['src'] for r in selected)
    sel_regions = Counter(r['region'] or 'UNKNOWN' for r in selected)
    print(f'selected per source: {dict(sel_by_src)}')
    print(f'selected per region: {dict(sel_regions)}')

    now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    names = [r['name'] for r in selected]
    with open('surge-nodes.conf', 'w', encoding='utf-8') as f:
        f.write('# Surge free-node subscription (auto-generated; do not edit)\n')
        f.write(f'# Generated: {now} (UTC)\n')
        f.write('# Filter: Asia only (HK/TW/JP/SG/KR and other Asia; '
                'mainland China excluded; unknown region dropped), every '
                'node connectivity-tested (TCP connect; TLS handshake '
                'for trojan/tls-vmess), sorted by latency ascending, '
                f'max {MAX_SELECT}\n')
        rate = (100.0 * len(passed) / len(asia)) if asia else 0.0
        f.write(f'# Tested: {len(asia)} Asia candidates -> {len(passed)} '
                f'passed ({rate:.1f}%)\n')
        if fallback_used:
            f.write(f'# Fallback: added {fallback_used} fastest tested '
                    f'non-Asia nodes to reach the {MIN_SELECT}-node '
                    f'minimum\n')
        for src in dict.fromkeys(s for s, _, _, _ in FEEDS):
            detail = ', '.join(
                f'{p}={sum(1 for r in selected if r["src"] == src and r["proto"] == p)}'
                for p in ('vmess', 'trojan', 'ss'))
            f.write(f'# Source {src}: {sel_by_src.get(src, 0)} selected '
                    f'({detail})\n')
        f.write('# Regions: ' + ', '.join(
            f'{k}={v}' for k, v in
            sorted(sel_regions.items(), key=lambda kv: -kv[1])) + '\n')
        f.write(f'# Total: {total} selected nodes\n')
        f.write('\n[Proxy]\n')
        f.write('\n'.join(r['line'] for r in selected) + '\n')
        f.write('\n[Proxy Group]\n')
        f.write('FreeNodes = select, ' + ', '.join(names) + '\n')
    print(f'wrote surge-nodes.conf with {total} proxies')
    return 0


if __name__ == '__main__':
    sys.exit(main())
