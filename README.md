# web-check-tui

Terminal viewer for [web-check](https://github.com/Lissy93/web-check) JSON results.

This is an unofficial, independent project. It is not affiliated with or endorsed by the web-check project.

## Requirements

- Python 3.11+
- One dependency: `textual` (installs `rich` automatically)

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```bash
python web_check_tui.py                     # browse ./results/
python web_check_tui.py results/file.json   # open a specific file
python web_check_tui.py --dir /path/to/results
```

## Live scan

Instead of reading a saved file, fetch checks straight from a running
[web-check](https://github.com/Lissy93/web-check) instance:

```bash
docker run -p 3000:3000 lissy93/web-check          # start an instance
python web_check_tui.py --scan example.com         # scan it live
python web_check_tui.py --scan example.com --save results/example.com.json
python web_check_tui.py --scan example.com --api http://my-host:3000
```

All 38 checks are fetched concurrently and opened in the same viewer.
`--api` defaults to `http://localhost:3000`.

While viewing a live scan, press **s** to save it to `results/<domain>.json`
so you can reopen it later without rescanning. (`--save` does the same up front.)

The first tab, **Advisories**, mirrors the web UI's advisory panel: findings grouped
as Critical, Issues, Warnings, Informational and Passes. The rules are a Python port
of web-check's own analysis rules (`advisories.py`); the `quality` rule is skipped
(it needs a Google API key the TUI doesn't fetch).

Checks shown, by tab: Overview (incl. social presence), Security (incl. mixed
content, trackers, data breaches), DNS (incl. CAA), Network (incl. resolved IP and
server location), TLS, Tech. `shodan` (Network tab, plus CVE advisories) needs `SHODAN_API_KEY` set on the web-check
server; without it that section just says it was skipped. `quality` and `screenshot` are
not fetched.

## Tests

```bash
python test_web_check_tui.py     # prints "ok" (or: pytest)
```

A small self-check; it doesn't launch the UI or contact a web-check instance. It covers:

- **Hostile data:** every tab builder is fed scan data with stray `[` brackets, strings where dicts are expected, and junk list items, and must still produce valid markup.
- **Filenames:** `_safe_filename` turns URLs into tidy names (`https://example.com/` → `example.com`).
- **API URLs:** `_build_api_url` encodes the scan URL and trims a trailing slash on the base.
- **Endpoint coverage:** every data key a tab reads has a matching entry in `LIVE_ENDPOINTS`.

## Credits

All of the checks and the API this tool reads come from
[web-check](https://github.com/Lissy93/web-check) by
[Alicia Sykes (Lissy93)](https://github.com/Lissy93), released under the MIT license.
This project is only a terminal front end for it. Please star and support the
original: https://github.com/Lissy93/web-check

## License

MIT, see [LICENSE](LICENSE).
