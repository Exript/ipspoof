# Changelog

All notable changes to this project will be documented here.

## [1.0.0] - 2026-09-15

### Added
- Initial release
- Header discovery (100+ headers)
- IP fuzzing (Phase 2)
- Baseline anomaly detection

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

## [2.0.1] - 2026-09-19

### Fixed
- Images now use absolute GitHub raw URLs so they render correctly on PyPI
## [2.0.2] - 2026-09-19

### Fixed
- Added content-type to readme field so PyPI renders markdown correctly
- Fixed LICENSE link to use absolute GitHub URL
## [2.0.3] - 2026-09-19

### Fixed
- `NameError: name 'n' is not defined` caused by unescaped `{n}` in the EPILOG f-string
- Duplicate banner print in `main()`

### Changed
- Banner now uses dynamically aligned width so version changes don't break the box
