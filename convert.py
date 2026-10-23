#!/usr/bin/env python3
"""Convert free-node feeds (vmess/trojan/ss only) into a curated Surge sub.

Pipeline:
  1. fetch the pre-split feeds, convert to Surge lines (deduped on the
     full config body); every record also keeps a sing-box outbound.
  2. Asia candidates: the ORIGINAL remark identifies an Asian region OR
     the server IP's geolocation (ip-api.com) is Asian; mainland China
     excluded in both channels; unknown in both -> not a candidate.
  3. Prescreen: TCP connect for every candidate (trojan and tls-vmess
     must also finish a TLS handshake); keep the 300 fastest.
  4. End-to-end: sing-box (downloaded at runtime) serves each candidate
     as a real proxy; a node passes only if an HTTP request through it
     returns 200/204. Publish passes, Asia first, by end-to-end latency,
     at most 120. If fewer than 20 Asian nodes pass, the fastest
     non-Asian end-to-end passes top the list up to 20.
  5. If sing-box cannot be obtained, degrade to the prescreen result
     (geo pool + TCP/TLS + cap 150) and say so in the header.

Output: surge-nodes.conf in the current directory, with an Auto url-test
group so the phone re-picks live nodes itself. Header comments record
every stage count. Exits non-zero when the final selection is empty, so
an empty subscription is never published. Standard library only,
except the sing-box binary fetched at runtime.
"""
import asyncio
import base64
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import statistics
import subprocess
import sys
import tarfile
import tempfile
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

MAX_SELECT = 120        # cap on published end-to-end passes
MIN_TOTAL = 20          # top up with non-Asian passes below this
E2E_POOL = 300          # fastest prescreen passes that get e2e-tested
CONNECT_TIMEOUT = 3.0   # seconds, per attempt
TEST_DEADLINE = 540     # seconds, whole prescreen phase
CONCURRENCY = 64
FALLBACK_POOL = 800     # non-Asia records prescreened for the top-up
TOPUP_E2E_POOL = 100    # fastest of those that get e2e-tested
FALLBACK_MAX = 150      # degraded-mode cap (no sing-box available)
TEST_URL = 'http://cp.cloudflare.com/generate_204'
E2E_BATCH = 40
E2E_BASE_PORT = 20000
E2E_CURL_TIMEOUT = 8    # seconds per proxied request
E2E_DEADLINE = 1800     # seconds, whole end-to-end phase
SINGBOX_FALLBACK_VERSION = '1.14.3'


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
# meta carries what later stages need: host/port for the connect test,
# tls+sni for the handshake gate, the ORIGINAL remark for region ID, and
# 'sb', a sing-box outbound dict for the end-to-end traffic test.

_VMESS_SECURITY = {'auto', 'aes-128-gcm', 'chacha20-poly1305', 'none',
                   'zero'}


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
    # sing-box outbound
    try:
        aid = int(cfg.get('aid') or 0)
    except Exception:
        aid = 0
    scy = str(cfg.get('scy') or 'auto')
    sb = {'type': 'vmess', 'server': str(host), 'server_port': int(port),
          'uuid': cfg.get('id', ''),
          'security': scy if scy in _VMESS_SECURITY else 'auto',
          'alter_id': aid}
    if cfg.get('tls') == 'tls':
        t = {'enabled': True, 'insecure': False}
        sn = cfg.get('sni') or cfg.get('host')
        if sn:
            t['server_name'] = sn
        if cfg.get('alpn'):
            t['alpn'] = [a.strip() for a in str(cfg['alpn']).split(',')
                         if a.strip()]
        sb['tls'] = t
    net = cfg.get('net') or 'tcp'
    if net == 'ws':
        tr = {'type': 'ws', 'path': cfg.get('path') or '/'}
        if cfg.get('host'):
            tr['headers'] = {'Host': cfg['host']}
        sb['transport'] = tr
    elif net == 'grpc':
        sb['transport'] = {'type': 'grpc',
                          'service_name': cfg.get('path') or ''}
    elif net in ('h2', 'http'):
        tr = {'type': 'http', 'path': cfg.get('path') or '/'}
        if cfg.get('host'):
            tr['host'] = [cfg['host']]
        sb['transport'] = tr
    elif net == 'httpupgrade':
        tr = {'type': 'httpupgrade', 'path': cfg.get('path') or '/'}
        if cfg.get('host'):
            tr['host'] = cfg['host']
        sb['transport'] = tr
    elif net == 'quic':
        sb['transport'] = {'type': 'quic'}
    meta['sb'] = sb
    return ', '.join(parts), meta


def conv_trojan(line, idx):
    p = urllib.parse.urlparse(line)
    if not p.hostname or not p.port:
        return None
    raw_frag = frag_name(line)
    name = uniq(clean_name(raw_frag, 'trojan', idx))
    q = urllib.parse.parse_qs(p.query)
    sni = q.get('sni', [p.hostname])[0]
    pw = urllib.parse.unquote(p.username or '')
    parts = [f'{name} = trojan', p.hostname, str(p.port),
             f'password={pw}', 'tls=true']
    parts.append(f'sni={sni}')
    meta = {'host': p.hostname, 'port': int(p.port), 'tls': True,
            'sni': sni, 'remark': urllib.parse.unquote(raw_frag)}
    insecure = q.get('allowInsecure', ['0'])[0] in ('1', 'true')
    tls = {'enabled': True, 'insecure': insecure}
    sn = q.get('sni', [None])[0] or q.get('peer', [None])[0]
    if sn:
        tls['server_name'] = sn
    sb = {'type': 'trojan', 'server': p.hostname,
          'server_port': int(p.port), 'password': pw, 'tls': tls}
    ttype = q.get('type', ['tcp'])[0]
    if ttype == 'ws':
        tr = {'type': 'ws', 'path': q.get('path', ['/'])[0]}
        if q.get('host', [''])[0]:
            tr['headers'] = {'Host': q['host'][0]}
        sb['transport'] = tr
    elif ttype == 'grpc':
        sb['transport'] = {'type': 'grpc',
                          'service_name': q.get('serviceName', [''])[0]}
    meta['sb'] = sb
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
            'remark': urllib.parse.unquote(raw_frag),
            'sb': {'type': 'shadowsocks', 'server': host,
                   'server_port': int(port), 'method': method,
                   'password': pw}}
    return ', '.join([f'{name} = ss', host, port,
                      f'encrypt-method={method}', f'password={pw}']), meta


CONV = {'vmess': conv_vmess, 'trojan': conv_trojan, 'ss': conv_ss}


# ---------------- connectivity prescreen (TCP + TLS) ----------------

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


# ---------------- geolocation (ip-api.com batch) ----------------

async def _resolve_hosts(hosts):
    """Resolve unique hostnames to one IPv4 each (as-is for IP hosts)."""
    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(128)

    async def one(h):
        if _is_ip(h):
            return h, h
        async with sem:
            try:
                infos = await asyncio.wait_for(
                    loop.getaddrinfo(h, None, type=socket.SOCK_STREAM),
                    timeout=6)
            except Exception:
                return h, None
            for info in infos or []:
                ip = info[4][0]
                if ':' not in ip:
                    return h, ip
            return h, (infos[0][4][0] if infos else None)

    return dict(await asyncio.gather(*[one(h) for h in hosts]))


def _geo_lookup(ips):
    """countryCode per IP via ip-api.com/batch (<=100 per call, free
    tier 45 req/min: keep >=1.4s between batch starts; one retry)."""
    out = {}
    uniq = sorted(set(ips))
    last = 0.0
    for i in range(0, len(uniq), 100):
        chunk = uniq[i:i + 100]
        wait = 1.4 - (time.time() - last)
        if wait > 0:
            time.sleep(wait)
        last = time.time()
        for attempt in range(2):
            try:
                body = json.dumps(
                    [{'query': ip, 'fields': 'status,countryCode,query'}
                     for ip in chunk]).encode()
                req = urllib.request.Request(
                    'http://ip-api.com/batch', data=body,
                    headers={'Content-Type': 'application/json',
                             'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=30) as r:
                    arr = json.loads(r.read().decode('utf-8', 'replace'))
                for item in arr:
                    if item.get('status') == 'success':
                        out[item['query']] = item.get('countryCode')
                break
            except Exception as e:
                if attempt == 0:
                    time.sleep(10)
                else:
                    print(f'WARN: geo batch failed: {e}', file=sys.stderr)
    return out


def annotate_geo(records):
    """Attach ip / geo / asia classification to every record.

    Asia candidate = remark channel OR geo channel says Asia, with CN
    in either channel vetoing. Returns the number of records that got a
    country from geolocation."""
    hosts = sorted({r['host'] for r in records})
    host_ip = asyncio.run(_resolve_hosts(hosts))
    ip_cc = _geo_lookup([ip for ip in host_ip.values() if ip])
    hits = 0
    for r in records:
        ip = host_ip.get(r['host'])
        r['ip'] = ip
        cc = ip_cc.get(ip) if ip else None
        r['geo'] = cc
        if cc:
            hits += 1
        remark = r['region']
        r['asia_remark'] = remark in ASIA_REGIONS
        r['asia_geo'] = cc in ASIA_REGIONS
        veto = remark == 'CN' or cc == 'CN'
        r['is_asia'] = (r['asia_remark'] or r['asia_geo']) and not veto
        if r['asia_geo']:
            r['disp'] = cc
        elif r['asia_remark']:
            r['disp'] = remark
        else:
            r['disp'] = cc or remark or 'UNKNOWN'
    return hits


# ---------------- sing-box end-to-end traffic test ----------------

def ensure_singbox(workdir):
    """Download the latest stable sing-box (linux-amd64) from GitHub
    Releases; fall back to a pinned version if the API is unreachable.
    Returns (binary path, version)."""
    ver = SINGBOX_FALLBACK_VERSION
    try:
        req = urllib.request.Request(
            'https://api.github.com/repos/SagerNet/sing-box/releases/latest',
            headers={'User-Agent': 'Mozilla/5.0'})
        rel = json.loads(urllib.request.urlopen(req, timeout=30)
                         .read().decode('utf-8', 'replace'))
        tag = (rel.get('tag_name') or '').lstrip('v')
        if tag:
            ver = tag
    except Exception as e:
        print(f'WARN: sing-box latest lookup failed ({e}); '
              f'using pinned {ver}')
    url = (f'https://github.com/SagerNet/sing-box/releases/download/'
           f'v{ver}/sing-box-{ver}-linux-amd64.tar.gz')
    tgz = os.path.join(workdir, 'sing-box.tar.gz')
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req, timeout=300) as r, \
            open(tgz, 'wb') as f:
        shutil.copyfileobj(r, f)
    with tarfile.open(tgz) as tf:
        tf.extractall(workdir)
    for root, _, files in os.walk(workdir):
        if 'sing-box' in files:
            p = os.path.join(root, 'sing-box')
            os.chmod(p, 0o755)
            return p, ver
    raise RuntimeError('sing-box binary not found in release tarball')


def _batch_config(recs, base_port):
    inbounds, outbounds, rules = [], [], []
    for i, r in enumerate(recs):
        ob = dict(r['sb'])
        ob['tag'] = f'o{i}'
        outbounds.append(ob)
        inbounds.append({'type': 'socks', 'tag': f'i{i}',
                         'listen': '127.0.0.1',
                         'listen_port': base_port + i})
        rules.append({'inbound': [f'i{i}'], 'outbound': f'o{i}'})
    return {'log': {'disabled': True}, 'inbounds': inbounds,
            'outbounds': outbounds, 'route': {'rules': rules}}


def _write_cfg(workdir, name, cfg):
    p = os.path.join(workdir, name)
    with open(p, 'w', encoding='utf-8') as f:
        json.dump(cfg, f)
    return p


def _sb_check(sb, workdir, recs, tag):
    p = _write_cfg(workdir, f'chk-{tag}.json',
                   _batch_config(recs, E2E_BASE_PORT))
    r = subprocess.run([sb, 'check', '-c', p],
                       capture_output=True, timeout=60)
    return r.returncode == 0


async def _probe(port, url):
    """One real request through the node's socks port; returns total
    time in ms when the proxy answers 200/204, else None.

    The probe must be immune to the runner's own proxy environment:
    strip *_proxy variables and pass --noproxy '' (empty list: nothing
    bypasses) so the request can never skip the node under test or leak
    through a local egress proxy (which would fake a pass)."""
    env = {k: v for k, v in os.environ.items()
           if 'proxy' not in k.lower()}
    try:
        proc = await asyncio.create_subprocess_exec(
            'curl', '-s', '-o', '/dev/null',
            '-w', '%{http_code} %{time_total}',
            '--max-time', str(E2E_CURL_TIMEOUT),
            '--noproxy', '',
            '-x', f'socks5h://127.0.0.1:{port}', url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL, env=env)
        out, _ = await asyncio.wait_for(
            proc.communicate(), timeout=E2E_CURL_TIMEOUT + 10)
        parts = out.decode('utf-8', 'replace').split()
        code, secs = int(parts[0]), float(parts[1])
        if code in (200, 204):
            return secs * 1000.0
    except Exception:
        pass
    return None


async def _probe_all(recs, base_port, url):
    return await asyncio.gather(
        *[_probe(base_port + i, url) for i in range(len(recs))])


def _run_batch(sb, workdir, recs, tag, url):
    """Start sing-box for one checked batch, probe every node, kill."""
    p = _write_cfg(workdir, f'run-{tag}.json',
                   _batch_config(recs, E2E_BASE_PORT))
    proc = subprocess.Popen([sb, 'run', '-c', p],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE)
    try:
        ready = False
        for _ in range(40):
            if proc.poll() is not None:
                break
            try:
                s = socket.create_connection(('127.0.0.1', E2E_BASE_PORT),
                                             timeout=0.25)
                s.close()
                ready = True
                break
            except Exception:
                time.sleep(0.25)
        if not ready:
            err = ''
            if proc.poll() is not None and proc.stderr:
                try:
                    err = proc.stderr.read().decode(
                        'utf-8', 'replace')[:300]
                except Exception:
                    pass
            print(f'WARN: sing-box batch {tag} did not start: {err}')
            return [None] * len(recs)
        return asyncio.run(_probe_all(recs, E2E_BASE_PORT, url))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        time.sleep(0.3)


def e2e_phase(sb, workdir, recs, url, deadline, prefix):
    """End-to-end test every record (sets rec['e2e'] = latency ms or
    None). A batch whose config sing-box rejects is bisected until the
    offending nodes are isolated and marked failed. Returns the number
    of records actually traffic-tested."""
    tested = 0

    def process(batch, tag):
        nonlocal tested
        if not batch or time.time() > deadline:
            return
        if not _sb_check(sb, workdir, batch, tag):
            if len(batch) == 1:
                batch[0]['e2e'] = None
                tested += 1
                return
            mid = len(batch) // 2
            process(batch[:mid], tag + 'a')
            process(batch[mid:], tag + 'b')
            return
        lats = _run_batch(sb, workdir, batch, tag, url)
        tested += len(batch)
        for r, lat in zip(batch, lats):
            r['e2e'] = lat

    for i in range(0, len(recs), E2E_BATCH):
        if time.time() > deadline:
            print('WARN: end-to-end deadline reached; '
                  'remaining candidates untested')
            break
        process(recs[i:i + E2E_BATCH], f'{prefix}{i // E2E_BATCH}')
    return tested


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

    total_all = len(records)
    print(f'records after conversion+dedupe: {total_all}')

    # ---- stage 2: Asia candidates = remark region U IP geolocation ----
    geo_hits = annotate_geo(records)
    asia = [r for r in records if r['is_asia']]
    others = [r for r in records if not r['is_asia']]
    n_remark = sum(1 for r in records if r['asia_remark'])
    n_geo = sum(1 for r in records if r['asia_geo'])
    print(f'geo: {geo_hits}/{total_all} records geolocated')
    print(f'asia candidates: {len(asia)} (remark-asia {n_remark}, '
          f'geo-asia {n_geo})')

    # ---- stage 3: prescreen (TCP connect + TLS handshake) ----
    passed = asyncio.run(run_tests(asia)) if asia else []
    passed.sort(key=lambda r: r['latency'])
    print(f'asia prescreen passed: {len(passed)}/{len(asia)}')
    pool = passed[:E2E_POOL]

    # ---- stage 4: end-to-end traffic test via sing-box ----
    workdir = tempfile.mkdtemp(prefix='surge-e2e-')
    sb_path, sb_ver, sb_err = None, None, None
    try:
        sb_path, sb_ver = ensure_singbox(workdir)
        print(f'sing-box {sb_ver} ready')
    except Exception as e:
        sb_err = str(e)
        print(f'WARN: sing-box unavailable ({e}); degrading to '
              f'prescreen-only selection', file=sys.stderr)

    selected = []
    topup_used = 0
    e2e_tested = 0
    e2e_passed = []
    if sb_path:
        deadline = time.time() + E2E_DEADLINE
        e2e_tested += e2e_phase(sb_path, workdir, pool, TEST_URL,
                                deadline, 'a')
        e2e_passed = [r for r in pool if r.get('e2e') is not None]
        e2e_passed.sort(key=lambda r: r['e2e'])
        if e2e_passed:
            lats = [r['e2e'] for r in e2e_passed]
            print(f'asia e2e passed: {len(e2e_passed)}; latency ms '
                  f'min={min(lats):.0f} median={statistics.median(lats):.0f} '
                  f'max={max(lats):.0f}')
        selected = e2e_passed[:MAX_SELECT]
        if len(selected) < MIN_TOTAL:
            need = MIN_TOTAL - len(selected)
            print(f'asia e2e passed < {MIN_TOTAL}; prescreening '
                  f'{min(len(others), FALLBACK_POOL)} non-asia for top-up')
            fb_tcp = asyncio.run(run_tests(others[:FALLBACK_POOL])) \
                if others else []
            fb_tcp.sort(key=lambda r: r['latency'])
            fb_pool = fb_tcp[:TOPUP_E2E_POOL]
            e2e_phase(sb_path, workdir, fb_pool, TEST_URL, deadline, 'b')
            fb_ok = [r for r in fb_pool if r.get('e2e') is not None]
            fb_ok.sort(key=lambda r: r['e2e'])
            add = fb_ok[:need]
            topup_used = len(add)
            selected = selected + add
            print(f'top-up added: {topup_used}')
    else:
        # Degraded: no real-traffic proof, prescreen order only.
        selected = passed[:FALLBACK_MAX]

    total = len(selected)
    print(f'selected total: {total}')
    shutil.rmtree(workdir, ignore_errors=True)
    if total == 0:
        print('ERROR: 0 nodes survived curation; not writing output',
              file=sys.stderr)
        return 1

    sel_by_src = Counter(r['src'] for r in selected)
    sel_regions = Counter(r['disp'] for r in selected)
    print(f'selected per source: {dict(sel_by_src)}')
    print(f'selected per region: {dict(sel_regions)}')

    now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    names = [r['name'] for r in selected]
    with open('surge-nodes.conf', 'w', encoding='utf-8') as f:
        f.write('# Surge free-node subscription (auto-generated; do not edit)\n')
        f.write(f'# Generated: {now} (UTC)\n')
        f.write(f'# Pipeline: {total_all} converted -> {len(asia)} Asia '
                f'candidates (remark {n_remark} + geo {n_geo}) -> '
                f'{len(passed)} passed TCP/TLS prescreen -> '
                f'{e2e_tested} end-to-end tested -> '
                f'{len(e2e_passed)} end-to-end passed\n')
        if sb_path:
            f.write(f'# End-to-end: real traffic via sing-box {sb_ver}; '
                    f'only nodes that returned HTTP 200/204 for '
                    f'{TEST_URL} through the actual proxy protocol are '
                    f'published, Asia first, sorted by end-to-end '
                    f'latency, max {MAX_SELECT}\n')
        else:
            f.write(f'# WARNING: end-to-end test unavailable '
                    f'({sb_err}); selection is TCP/TLS-prescreen only, '
                    f'max {FALLBACK_MAX}\n')
        if topup_used:
            f.write(f'# Top-up: added {topup_used} fastest non-Asia '
                    f'end-to-end passes to reach the {MIN_TOTAL}-node '
                    f'minimum\n')
        f.write(f'# Geolocation: server-IP country via ip-api.com '
                f'({geo_hits}/{total_all} records); mainland China '
                f'excluded in both remark and geo channels\n')
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
        f.write('Auto = url-test, ' + ', '.join(names) +
                f', url={TEST_URL}, interval=600, tolerance=100\n')
        f.write('FreeNodes = select, Auto, ' + ', '.join(names) + '\n')
    print(f'wrote surge-nodes.conf with {total} proxies')
    return 0


if __name__ == '__main__':
    sys.exit(main())
