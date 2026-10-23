#!/usr/bin/env python3
"""Convert free-node feeds (vmess/trojan/ss only) into a Surge subscription.

Sources are pre-split by protocol. Only protocols Surge can use natively are
fetched (vmess / trojan / ss); vless, ssr and reality are never pulled in.
Output: surge-nodes.conf in the current directory, with a header comment
block recording generation time (UTC), per-source node counts and the total.

Standard library only. If a single feed fails, it is counted as 0 and the
rest still convert; the script exits non-zero only when the grand total
is 0, so an empty subscription is never published.
"""
import base64
import json
import os
import sys
import urllib.parse
import urllib.request
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
    return ', '.join(parts)


def conv_trojan(line, idx):
    p = urllib.parse.urlparse(line)
    if not p.hostname or not p.port:
        return None
    name = uniq(clean_name(frag_name(line), 'trojan', idx))
    q = urllib.parse.parse_qs(p.query)
    parts = [f'{name} = trojan', p.hostname, str(p.port),
             f"password={urllib.parse.unquote(p.username or '')}", 'tls=true']
    parts.append(f"sni={q.get('sni', [p.hostname])[0]}")
    return ', '.join(parts)


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
    name = uniq(clean_name(frag_name(line), 'ss', idx))
    return ', '.join([f'{name} = ss', host, port,
                      f'encrypt-method={method}', f'password={pw}'])


CONV = {'vmess': conv_vmess, 'trojan': conv_trojan, 'ss': conv_ss}


def main():
    proxies = []
    seen_body = set()
    feed_counts = []          # (source label, proto, converted count)
    totals = {}               # source label -> converted count
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
                pl = CONV[proto](line, idx)
            except Exception:
                pl = None
            if not pl:
                continue
            body = pl.split(' = ', 1)[1]  # dedupe on full config, keep 1st name
            if body in seen_body:
                continue
            seen_body.add(body)
            proxies.append(pl)
            ok += 1
        feed_counts.append((src, proto, ok))
        totals[src] = totals.get(src, 0) + ok
        print(f'{src} {proto}: {ok}')

    total = len(proxies)
    print(f'total: {total}')
    if total == 0:
        print('ERROR: 0 usable nodes from all sources; not writing output',
              file=sys.stderr)
        return 1

    now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    names = [pl.split(' = ', 1)[0] for pl in proxies]
    with open('surge-nodes.conf', 'w', encoding='utf-8') as f:
        f.write('# Surge free-node subscription (auto-generated; do not edit)\n')
        f.write(f'# Generated: {now} (UTC)\n')
        for src, cnt in totals.items():
            detail = ', '.join(f'{p}={c}' for s, p, c in feed_counts if s == src)
            f.write(f'# Source {src}: {cnt} usable nodes ({detail})\n')
        f.write(f'# Total: {total} usable nodes\n')
        f.write('\n[Proxy]\n')
        f.write('\n'.join(proxies) + '\n')
        f.write('\n[Proxy Group]\n')
        f.write('FreeNodes = select, ' + ', '.join(names) + '\n')
    print(f'wrote surge-nodes.conf with {total} proxies')
    return 0


if __name__ == '__main__':
    sys.exit(main())
