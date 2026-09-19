# Changelog

All notable changes to this project will be documented here.

## [2.0.0] - 2026-09-19

### Added
- Proxy rotation (`--proxy-file`, `--proxy`)
- Tor SOCKS5 support (`--tor`) with identity rotation (`--tor-new-every`)
- Rate limiting (`--rate`)
- XFF chain variations (`--chain`)
- Body regex detection (`--body-regex`)
- Body hash detection (`--body-hash`)
- POST/PUT/PATCH support (`-X`, `-d`, `--json`)
- Extra static headers (`-H`)
- JSON output (`-o`)
- Interactive mode (`-i`)
- Size tolerance control (`--size-tol`)

### Changed
- Renamed from `ip-spoof.py` to `ipspoof`
- Installable via `pipx install ipspoof`
- English-only output

## [1.0.0] - 2026-09-18

### Added
- Initial release
- Header discovery (100+ headers)
- IP fuzzing (Phase 2)
- Baseline anomaly detection
