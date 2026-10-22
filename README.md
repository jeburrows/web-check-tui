# web-check-tui

Terminal viewer for [web-check](https://github.com/Lissy93/web-check) JSON results.

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

All 37 checks are fetched concurrently and opened in the same viewer.
`--api` defaults to `http://localhost:3000`.

While viewing a live scan, press **s** to save it to `results/<domain>.json`
so you can reopen it later without rescanning. (`--save` does the same up front.)

Checks shown, by tab: Overview (incl. social presence), Security (incl. mixed
content, trackers, data breaches), DNS (incl. CAA), Network (incl. resolved IP and
server location), TLS, Tech. Checks that need server-side API keys or a browser
(`shodan`, `quality`, `screenshot`) are not fetched.
