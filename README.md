# ipspoof

> HTTP header/IP allowlist bypass discovery tool for authorized security testing.

[![PyPI version](https://img.shields.io/pypi/v/ipspoof)](https://pypi.org/project/ipspoof/)
[![PyPI - Python versions](https://img.shields.io/pypi/pyversions/ipspoof)](https://pypi.org/project/ipspoof/)
[![Downloads](https://img.shields.io/pypi/dm/ipspoof)](https://pypi.org/project/ipspoof/)
[![Python](https://img.shields.io/badge/python-3.8+-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey)]()

  ![IPSpof Banner](https://raw.githubusercontent.com/Exript/ipspoof/main/banner.svg)

`ipspoof` helps pentesters and bug bounty hunters quickly identify which HTTP header a web application trusts for client-IP-based access control, and which IP range bypasses the allowlist. Common in labs, CTFs, and real-world engagements where you see messages like:

```
Your IP is not allowed to use this webservice. Only 10.10.10.x is allowed
```

![ipspoof demo](https://raw.githubusercontent.com/Exript/ipspoof/main/docs/images/1.jpeg)

---

## Features

- **Header discovery** — tests 100+ client-IP headers (`X-Forwarded-For`, `X-Real-IP`, `Forwarded`, `Client-IP`, `CF-Connecting-IP`, etc.) with a curated set of trusted IP values.
- **IP fuzzing** — once a working header is found, brute-forces the allowed IP range (e.g. `10.10.10.1-254`).
- **Smart anomaly detection** — catches bypasses by status change, size change, body hash, or body regex.
- **XFF chain variations** — `1.2.3.4, <ip>`, `<ip>, 1.2.3.4`, `for=<ip>`.
- **POST/PUT/PATCH support** — works against login forms and API endpoints.
- **Proxy rotation** — round-robin through a proxy list.
- **Tor support** — route through SOCKS5 with automatic identity rotation.
- **Rate limiting** — avoid bans during brute-force.
- **JSON output** — machine-readable results for reporting.
- **Interactive mode** — guided prompts for quick runs.

![ipspoof features](https://raw.githubusercontent.com/Exript/ipspoof/main/docs/images/2.jpeg)

---

## Installation

### pipx (recommended)

```bash
pipx install ipspoof
```

### pip

```bash
pip install ipspoof
```
### uv
```bash
uv tool install ipspoof
```

### From source

```bash
git clone https://github.com/Exript/ipspoof.git
cd ipspoof
pipx install .
```

For Tor support:

```bash
pipx install "ipspoof[tor]"
```

### pipx vs uvx vs uv tool

| Feature | pipx | uvx | uv tool |
|---------|------|-----|---------|
| One-off run | `pipx run ipspoof` | `uvx ipspoof` | — |
| Install permanently | `pipx install ipspoof` | — | `uv tool install ipspoof` |
| Speed | Slow (pip backend) | ⚡ Fast (Rust) | ⚡ Fast |
| Cache | 14-day TTL | No TTL | No TTL |
| Python auto-install | Optional | ✅ Built-in | ✅ Built-in |
| Cross-platform | ✅ | ✅ | ✅ |

**TL;DR:** `uvx` for one-off runs, `uv tool install` for permanent installs, `pipx` if you already use it.
---

## Usage

### Basic

```bash
ipspoof -u http://target/login.php --follow
```

Output:

![ipspoof output](https://raw.githubusercontent.com/Exript/ipspoof/main/docs/images/3.jpeg)

### Full pipeline (header discovery + IP fuzz)

```bash
ipspoof -u http://target/login.php \
  --phase2 --ip-pattern "10.10.10.{n}" --ip-range 1-254 \
  --follow
```

### POST login attempt

```bash
ipspoof -u http://target/login.php \
  -X POST -d "username=admin&password=admin" \
  --body-regex "dashboard|welcome" \
  --follow
```

### Tor + periodic identity rotation

```bash
ipspoof -u http://target/ --tor --tor-new-every 10
```

### Proxy list + rate limit

```bash
ipspoof -u http://target/ --proxy-file proxies.txt --rate 30
```

### Interactive

```bash
ipspoof -i
```

Output:

![ipspoof interactive output](https://raw.githubusercontent.com/Exript/ipspoof/main/docs/images/4.jpeg)

---

## Options

| Flag | Description |
|------|-------------|
| `-u, --url` | Target URL |
| `-i, --interactive` | Interactive mode |
| `-t, --threads` | Concurrent threads (default 30) |
| `--timeout` | Request timeout (default 8s) |
| `--follow` | Follow redirects |
| `-c, --cookie` | Cookie string |
| `-X, --method` | HTTP method (default GET) |
| `-d, --data` | Form data (for POST) |
| `--json` | JSON body (for POST) |
| `-H, --header` | Extra static header (repeatable) |
| `--proxy` | Single proxy |
| `--proxy-file` | Proxy list file |
| `--tor` | Route through Tor SOCKS5 |
| `--tor-new-every N` | Rotate Tor identity every N requests |
| `--rate N` | Max requests per second |
| `--body-regex` | Only treat body regex match as HIT |
| `--body-hash` | Treat hash change as HIT |
| `--size-tol` | Size tolerance (default 0.05) |
| `--chain` | Try XFF chain variations |
| `--ip` | IPs for Phase 1 (repeatable) |
| `--phase2` | Run IP fuzz phase |
| `--ip-pattern` | IP pattern (default `10.10.10.{n}`) |
| `--ip-range` | IP range (default `1-254`) |
| `-o, --output` | Save results as JSON |

---

## Tor setup (optional)

For `--tor-new-every`, add to `/etc/tor/torrc`:

```
ControlPort 9051
CookieAuthentication 0
```

Then:

```bash
sudo systemctl restart tor
```

Without this, `--tor` still works but `--tor-new-every` will only print a warning.

---

## How it works

1. **Baseline** — sends a request with no spoof headers. Records status, size, and body hash of the "deny" response.
2. **Phase 1** — for each (header, trusted IP) pair, sends a request and compares the response against baseline. Any response with a different status, size, hash, or regex match is flagged as a HIT.
3. **Phase 2** — takes the working header(s) from Phase 1 and brute-forces the IP range you specify.

The tool never sends anything malicious — it only adds HTTP headers to ordinary requests.

---

## Legal

This tool is for **authorized security testing only**. Use it against:

- Systems you own
- Systems you have explicit written permission to test
- CTF/lab environments designed for testing

Unauthorized use against third-party systems is illegal in most jurisdictions. The author takes no responsibility for misuse.

---

## Contributing

PRs welcome. Please open an issue first for major changes.

```bash
git clone https://github.com/Exript/ipspoof.git
cd ipspoof
pip install -e ".[dev]"
```

---

## License

MIT — see [LICENSE](https://github.com/Exript/ipspoof/blob/main/LICENSE).
