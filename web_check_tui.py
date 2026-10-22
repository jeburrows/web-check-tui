#!/usr/bin/env python3
"""
web-check-tui — Terminal viewer for web-check JSON results.

Usage:
  python web_check_tui.py                  # Browse ./results/ folder
  python web_check_tui.py results/file.json  # Open a specific file
  python web_check_tui.py --dir /path/to/results
"""

import json
import argparse
import sys
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from textual.app import App, ComposeResult
from textual.screen import Screen
from textual.widgets import (
    Header, Footer, TabbedContent, TabPane,
    Static, ListView, ListItem, Label,
)
from textual.containers import VerticalScroll, Vertical
from textual.binding import Binding
from textual import on

from advisories import analyze, SEVERITIES


def _esc(s) -> str:
    """Escape dynamic text so it's never parsed as markup.

    rich.markup.escape only escapes *well-formed* ``[tag]`` sequences and leaves
    unclosed/odd ones like ``[expires=...`` alone — but Textual's stricter parser
    (used by Static.update) rejects those. Escaping every ``[`` is parser-agnostic
    and bulletproof. ``]`` never needs escaping since only ``[`` opens a tag.
    """
    return str(s).replace("\\", "\\\\").replace("[", "\\[")


def _dict(x) -> dict:
    """Some API fields (e.g. ssl issuer/subject) are sometimes a string, not a
    dict. Return a real dict or an empty one so ``.get`` calls never blow up."""
    return x if isinstance(x, dict) else {}
from rich.text import Text as RichText


# ═══════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════

def _fmt_date(iso_str: str) -> str:
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.strftime("%b %d, %Y")
    except Exception:
        return iso_str or "—"


def _days_until(iso_str: str) -> Optional[int]:
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        return (dt - now).days
    except Exception:
        return None


def _parse_ssl_date(ssl_date: str) -> Optional[int]:
    """Parse SSL cert dates like 'Sep 22 17:31:18 2026 GMT'."""
    try:
        dt = datetime.strptime(ssl_date.strip(), "%b %d %H:%M:%S %Y %Z")
        now = datetime.utcnow()
        return (dt - now).days
    except Exception:
        return None


def _grade_color(grade: str) -> str:
    if not grade:
        return "white"
    g = grade.upper()
    if g.startswith("A"):
        return "bright_green"
    if g.startswith("B"):
        return "yellow"
    if g.startswith("C"):
        return "dark_orange"
    return "red"


def _trunc(s: str, n: int = 80) -> str:
    s = str(s)
    if len(s) > n:
        s = s[: n - 1] + "…"
    return _esc(s)  # escape AFTER truncating so an escape can't be split


def _safe_filename(scan_url: str) -> str:
    """Turn a scanned URL/domain into a tidy filename stem, e.g. example.com."""
    s = (scan_url or "scan").split("://", 1)[-1].strip("/")
    s = "".join(c if (c.isalnum() or c in ".-_") else "_" for c in s)
    return s or "scan"


def _mail_txt(mail: dict, marker: str) -> Optional[str]:
    """Find the first TXT record containing `marker`. txtRecords is a list of
    strings or list-of-strings (multi-chunk records), so flatten both."""
    for sub in (mail.get("txtRecords") or []):
        for t in (sub if isinstance(sub, list) else [sub]):
            if marker.lower() in str(t).lower():
                return str(t)
    return None


# ═══════════════════════════════════════════════════════════════
#  Live fetch — pull checks straight from a web-check API instance
# ═══════════════════════════════════════════════════════════════

# data-key -> /api/<endpoint>. Only the checks the TUI actually renders.
# Most are 1:1 with the API filename; the renamed ones are noted.
LIVE_ENDPOINTS: dict[str, str] = {
    "ssl": "ssl",
    "whois": "whois",            # overview "DOMAIN" section falls back to whois
    "dns": "dns",
    "dns-server": "dns-server",
    "dnssec": "dnssec",
    "hsts": "hsts",
    "http-security": "http-security",
    "security-txt": "security-txt",
    "threats": "threats",
    "block-lists": "block-lists",
    "txt-records": "txt-records",
    "subdomains": "subdomains",
    "ports": "ports",
    "headers": "headers",
    "cookies": "cookies",
    "trace-route": "trace-route",
    "tls-connection": "tls-connection",
    "tls-security-audit": "tls-labs",   # SSL-Labs style audit
    "tech-stack": "tech-stack",
    "mail-config": "mail-config",
    "robots-txt": "robots-txt",
    "sitemap": "sitemap",
    "archives": "archives",
    "status": "status",
    "redirects": "redirects",
    "rank": "rank",
    "firewall": "firewall",
    "social-tags": "social-tags",
    "carbon": "carbon",
    "linked-pages": "linked-pages",
    "caa-records": "caa-records",
    "mixed-content": "mixed-content",
    "trackers": "trackers",
    "social-presence": "social-presence",
    "location": "location",
    "get-ip": "get-ip",
    "breaches": "breaches",
}


def _build_api_url(api_base: str, endpoint: str, scan_url: str) -> str:
    qs = urllib.parse.urlencode({"url": scan_url})
    return f"{api_base.rstrip('/')}/api/{endpoint}?{qs}"


def _fetch_one(api_base: str, endpoint: str, scan_url: str, timeout: float) -> dict:
    url = _build_api_url(api_base, endpoint, scan_url)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception as e:  # one bad check shouldn't sink the scan
        return {"error": str(e)}


def fetch_live(scan_url: str, api_base: str, timeout: float = 30.0,
               progress=None) -> dict:
    """Hit every endpoint concurrently, return the same dict shape as the JSON file."""
    data: dict = {}
    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = {
            ex.submit(_fetch_one, api_base, ep, scan_url, timeout): key
            for key, ep in LIVE_ENDPOINTS.items()
        }
        for i, fut in enumerate(as_completed(futs), 1):
            key = futs[fut]
            data[key] = fut.result()
            if progress:
                progress(i, len(futs), key)
    return data


# ═══════════════════════════════════════════════════════════════
#  Tab content builders — each returns a Rich markup string
# ═══════════════════════════════════════════════════════════════

def _section(title: str) -> str:
    return f"[bold bright_cyan]■ {title}[/]"


def _note(d: dict) -> Optional[str]:
    """Envelope for checks that were skipped or failed ({"skipped": ..} / {"error": ..})."""
    if d.get("skipped"):
        return f"  [dim]{_trunc(d['skipped'], 72)}[/]"
    if d.get("error"):
        return f"  [yellow]{_trunc(d['error'], 72)}[/]"
    return None


_SEV_STYLE = {  # severity -> (label, colour, icon), mirroring the web UI's advisory panel
    "critical": ("Critical", "red", "✗"),
    "issue": ("Issues", "dark_orange", "!"),
    "warning": ("Warnings", "yellow", "▲"),
    "info": ("Informational", "cyan", "i"),
    "pass": ("Passes", "green", "✓"),
}


def tab_advisories(data: dict) -> str:
    findings = analyze(data)
    L: list[str] = []
    add = L.append
    counts = {s: sum(1 for f in findings if f[0] == s) for s in SEVERITIES}
    add("  ".join(f"[{_SEV_STYLE[s][1]}]{_SEV_STYLE[s][2]} {counts[s]} {_SEV_STYLE[s][0]}[/]"
                  for s in SEVERITIES))
    add("")
    for sev in SEVERITIES:
        items = [f for f in findings if f[0] == sev]
        if not items:
            continue
        label, color, icon = _SEV_STYLE[sev]
        add(f"[bold {color}]■ {label.upper()}  ({len(items)})[/]")
        for _, check, title, detail in items:
            add(f"  [{color}]{icon}[/] [white]{_esc(title)}[/]  [dim]{_esc(check)}[/]")
            if detail and sev != "pass":
                add(f"      [dim]{_esc(detail)}[/]")
        add("")
    return "\n".join(L)


def tab_overview(data: dict) -> str:
    L: list[str] = []
    add = L.append

    # Domain / WHOIS
    domain = data.get("domain") or {}
    whois = data.get("whois") or {}
    name = domain.get("domain") or whois.get("domain") or "Unknown"
    registrar = domain.get("registrar") or whois.get("registrar") or ""
    created = domain.get("created") or whois.get("created") or ""
    expires = domain.get("expires") or whois.get("expires") or ""
    ns_list = domain.get("nameservers") or whois.get("nameservers") or []

    add(_section("DOMAIN"))
    add(f"  [bold white]{_esc(str(name))}[/]")
    if registrar:
        add(f"  Registrar: [cyan]{_esc(str(registrar))}[/]")
    if created:
        add(f"  Created:   [white]{_esc(_fmt_date(created))}[/]")
    if expires:
        days = _days_until(expires)
        c = "green" if (days or 0) > 90 else "yellow" if (days or 0) > 30 else "red"
        day_str = f" [{c}]({days} days)[/]" if days is not None else ""
        add(f"  Expires:   [white]{_esc(_fmt_date(expires))}[/]{day_str}")
    if ns_list:
        add(f"  NS:        [dim]{_esc(', '.join(str(n) for n in ns_list[:4]))}[/]")
    # Domain lock status (EPP codes) — strip the trailing ICANN URL on each
    statuses = domain.get("status") or whois.get("status") or []
    if isinstance(statuses, str):
        statuses = [statuses]
    codes = [str(s).split()[0] for s in statuses if str(s).strip()]
    if codes:
        locked = any("Prohibited" in c for c in codes)
        c = "green" if locked else "yellow"
        add(f"  Status:    [{c}]{_esc(', '.join(codes))}[/]")
    add("")

    # Status
    status = data.get("status") or {}
    if status:
        is_up = status.get("isUp", False)
        code = status.get("responseCode", "")
        rt = status.get("responseTime", 0)
        icon, c = ("✓", "green") if is_up else ("✗", "red")
        add(_section("STATUS"))
        add(f"  [{c}]{icon} {'Online' if is_up else 'Offline'}[/]  "
            f"HTTP {code}  {rt:.0f} ms")
        add("")

    # Redirects
    redirects = (data.get("redirects") or {}).get("redirects", [])
    if redirects:
        add(_section("REDIRECT CHAIN"))
        for i, r in enumerate(redirects):
            prefix = "└─" if i == len(redirects) - 1 else "├─"
            add(f"  {prefix} [dim]{_esc(str(r))}[/]")
        add("")

    # Global rank
    ranks = (data.get("rank") or {}).get("ranks", [])
    if ranks:
        latest = ranks[0]
        add(_section("GLOBAL RANK"))
        add(f"  [bold white]#{latest.get('rank', 0):,}[/]  [dim]as of {_esc(str(latest.get('date', '')))}[/]")
        if len(ranks) >= 2:
            delta = ranks[0]["rank"] - ranks[-1]["rank"]
            if delta > 0:
                add(f"  [red]▲ +{delta:,} (ranking declined)[/] over {len(ranks)} days")
            elif delta < 0:
                add(f"  [green]▼ {abs(delta):,} (ranking improved)[/] over {len(ranks)} days")
            else:
                add("  [dim]— Stable[/]")
        add("")

    # Social tags
    social = data.get("social-tags") or {}
    if social:
        title = social.get("title") or social.get("ogTitle") or ""
        desc = social.get("description") or ""
        og_type = social.get("ogType") or ""
        canonical = social.get("canonicalUrl") or ""
        if title or desc:
            add(_section("SOCIAL TAGS"))
            if title:
                add(f"  Title:       [white]{_trunc(title, 72)}[/]")
            if og_type:
                add(f"  Type:        [dim]{_esc(str(og_type))}[/]")
            if canonical:
                add(f"  Canonical:   [dim]{_trunc(canonical, 72)}[/]")
            if desc:
                add(f"  Description: [dim]{_trunc(desc, 72)}[/]")
            add("")

    # Carbon
    carbon = data.get("carbon") or {}
    if carbon and not carbon.get("error"):
        stats = carbon.get("statistics") or {}
        co2 = (stats.get("co2") or {}).get("grid") or {}
        green = carbon.get("green", False)
        nbytes = carbon.get("bytes", 0)
        add(_section("CARBON FOOTPRINT"))
        c = "green" if green else "yellow"
        add(f"  Green hosting: [{c}]{'Yes' if green else 'No'}[/]")
        if nbytes:
            add(f"  Page size:     [white]{nbytes / 1024:.0f} KB[/]")
        if co2.get("grams"):
            add(f"  CO₂/visit:     [dim]{co2['grams']:.5f} g[/]")
        add("")

    # Social presence (profiles the site declares or that link back to it)
    sp = _dict(data.get("social-presence"))
    if sp:
        add(_section("SOCIAL PRESENCE"))
        profiles = [p for p in sp.get("profiles") or [] if isinstance(p, dict)]
        if not profiles:
            add(_note(sp) or "  [dim]None found[/]")
        for pr in profiles:
            ok = pr.get("exists", True)
            c, icon = ("green", "✓") if ok else ("yellow", "?")
            who = pr.get("handle") or pr.get("name") or ""
            extra = f"  [dim]{pr['followers']:,} followers[/]" \
                if isinstance(pr.get("followers"), int) else ""
            add(f"  [{c}]{icon}[/] [cyan]{_esc(str(pr.get('network', '?')))}[/] "
                f"[white]{_trunc(who, 48)}[/]{extra}")
        add("")

    return "\n".join(L)


def tab_security(data: dict) -> str:
    L: list[str] = []
    add = L.append

    # SSL Certificate
    ssl = data.get("ssl") or {}
    if ssl:
        issuer = _dict(ssl.get("issuer"))
        subject = _dict(ssl.get("subject"))
        is_valid = ssl.get("isValid", False)
        icon, c = ("✓", "green") if is_valid else ("✗", "red")
        add(_section("SSL CERTIFICATE"))
        add(f"  [{c}]{icon} {'Valid' if is_valid else 'Invalid'}[/]")
        issuer_name = issuer.get("O") or issuer.get("CN") or "Unknown"
        add(f"  Issuer:     [cyan]{_esc(str(issuer_name))}[/]")
        add(f"  Subject:    [white]{_esc(str(subject.get('CN', 'N/A')))}[/]")
        san = ssl.get("subjectaltname") or ""
        if san:
            add(f"  SAN:        [dim]{_trunc(san, 72)}[/]")
        valid_from = ssl.get("valid_from") or ""
        valid_to = ssl.get("valid_to") or ""
        if valid_from:
            add(f"  Valid from: [dim]{_esc(str(valid_from))}[/]")
        if valid_to:
            days = _parse_ssl_date(valid_to)
            dc = "green" if (days or 0) > 60 else "yellow" if (days or 0) > 14 else "red"
            day_str = f" [{dc}]({days} days)[/]" if days is not None else ""
            add(f"  Valid to:   [white]{_esc(str(valid_to))}[/]{day_str}")
        bits = ssl.get("bits")
        curve = ssl.get("nistCurve") or ssl.get("asn1Curve") or ""
        if bits:
            add(f"  Key:        [dim]{bits}-bit {_esc(str(curve))}[/]")
        sn = ssl.get("serialNumber") or ""
        if sn:
            add(f"  Serial:     [dim]{_esc(str(sn))}[/]")
        add("")

    # HSTS
    hsts = data.get("hsts") or {}
    if hsts:
        compatible = hsts.get("compatible", False)
        icon, c = ("✓", "green") if compatible else ("✗", "red")
        add(_section("HSTS"))
        add(f"  [{c}]{icon} {'Compatible' if compatible else 'Not compatible'}[/]")
        msg = hsts.get("message") or ""
        if msg:
            add(f"  [dim]{_trunc(msg, 72)}[/]")
        header = hsts.get("hstsHeader") or ""
        if header:
            add(f"  Header: [dim]{_esc(str(header))}[/]")
        add("")

    # DNSSEC
    dnssec = data.get("dnssec") or {}
    if dnssec:
        dnskey = (dnssec.get("DNSKEY") or {})
        ds = (dnssec.get("DS") or {})
        has_dnskey = dnskey.get("isFound", False)
        has_ds = ds.get("isFound", False)
        enabled = has_dnskey and has_ds
        c = "green" if enabled else "yellow"
        icon = "✓" if enabled else "⚠"
        add(_section("DNSSEC"))
        add(f"  [{c}]{icon} {'Enabled' if enabled else 'Not fully configured'}[/]")
        dk_c = "green" if has_dnskey else "red"
        ds_c = "green" if has_ds else "red"
        add(f"  DNSKEY: [{dk_c}]{'Found' if has_dnskey else 'Not found'}[/]"
            f"   DS: [{ds_c}]{'Found' if has_ds else 'Not found'}[/]")
        add("")

    # HTTP Security Headers
    http_sec = data.get("http-security") or {}
    if http_sec:
        add(_section("HTTP SECURITY HEADERS"))
        header_map = [
            ("contentSecurityPolicy",      "Content-Security-Policy"),
            ("strictTransportPolicy",      "Strict-Transport-Security"),
            ("xContentTypeOptions",        "X-Content-Type-Options"),
            ("xFrameOptions",              "X-Frame-Options"),
            ("xXSSProtection",             "X-XSS-Protection"),
            ("referrerPolicy",             "Referrer-Policy"),
            ("permissionsPolicy",          "Permissions-Policy"),
            ("crossOriginOpenerPolicy",    "Cross-Origin-Opener-Policy"),
            ("crossOriginResourcePolicy",  "Cross-Origin-Resource-Policy"),
            ("crossOriginEmbedderPolicy",  "Cross-Origin-Embedder-Policy"),
        ]
        for key, label in header_map:
            present = http_sec.get(key, False)
            ic, cc = ("✓", "green") if present else ("✗", "red")
            add(f"  [{cc}]{ic}[/] [dim]{label}[/]")
        add("")

    # Cookies (shown here for their security flags: Secure / HttpOnly / SameSite)
    cookies = data.get("cookies") or {}
    all_cookies = (cookies.get("headerCookies") or []) + (cookies.get("clientCookies") or [])
    all_cookies = [c for c in all_cookies if isinstance(c, dict)]
    if all_cookies:
        add(_section("COOKIES"))
        for c in all_cookies:
            name = c.get("name", "?")
            secure = c.get("secure", False)
            httponly = c.get("httpOnly", False)
            samesite = c.get("sameSite") or ""
            flags = []
            flags.append("[green]Secure[/]" if secure else "[red]!Secure[/]")
            flags.append("[green]HttpOnly[/]" if httponly else "[yellow]!HttpOnly[/]")
            if samesite:
                flags.append(f"[dim]SameSite={_esc(str(samesite))}[/]")
            add(f"  [white]{_esc(str(name))}[/]  {' '.join(flags)}")
        add("")

    # Security.txt
    sec_txt = data.get("security-txt") or {}
    if sec_txt:
        present = sec_txt.get("isPresent", False)
        c = "green" if present else "yellow"
        icon = "✓" if present else "⚠"
        add(_section("SECURITY.TXT"))
        add(f"  [{c}]{icon} {'Present' if present else 'Not present'}[/]")
        add("")

    # Firewall / WAF
    fw = data.get("firewall") or {}
    if fw:
        has_waf = fw.get("hasWaf", False)
        waf_name = fw.get("waf", "")
        add(_section("FIREWALL / WAF"))
        if has_waf:
            add(f"  [green]✓ WAF Detected:[/] [white]{_esc(str(waf_name))}[/]")
        else:
            add("  [yellow]⚠ No WAF detected[/]")
        add("")

    # Threats
    threats = data.get("threats") or {}
    if threats:
        add(_section("THREAT INTELLIGENCE"))
        phish = threats.get("phishTank") or {}
        in_db = str((phish.get("url0") or {}).get("in_database", "false")).lower()
        is_threat = in_db == "true"
        pt_c = "red" if is_threat else "green"
        pt_i = "✗" if is_threat else "✓"
        add(f"  [{pt_c}]{pt_i} PhishTank: {'Listed — THREAT' if is_threat else 'Not listed'}[/]")

        sb = threats.get("safeBrowsing") or {}
        if sb.get("skipped"):
            add("  [dim]⊘ Google Safe Browsing: skipped (no API key)[/]")
        elif sb.get("matches"):
            add("  [red]✗ Google Safe Browsing: Threat detected[/]")
        elif sb:
            add("  [green]✓ Google Safe Browsing: Clean[/]")

        uh = threats.get("urlHaus") or {}
        if uh.get("error"):
            add(f"  [dim]⊘ URLhaus: {_esc(str(uh['error']))}[/]")
        elif (uh.get("query_status") or "").lower() == "no_results":
            add("  [green]✓ URLhaus: Not listed[/]")
        add("")

    # Block lists
    blocklists = (data.get("block-lists") or {}).get("blocklists", [])
    if blocklists:
        blocked = [b for b in blocklists if isinstance(b, dict) and b.get("isBlocked")]
        add(_section("BLOCK LISTS"))
        if blocked:
            for b in blocked:
                add(f"  [red]✗ Blocked by {_esc(str(b['server']))}[/]")
        else:
            add(f"  [green]✓ Not blocked on any of {len(blocklists)} checked lists[/]")
        add("")

    # Email security (SPF / DKIM / DMARC, parsed from mail-config TXT records)
    mail = data.get("mail-config") or {}
    if mail:
        spf = _mail_txt(mail, "v=spf1")
        dmarc = _mail_txt(mail, "v=DMARC1")
        dkim = _mail_txt(mail, "v=DKIM1") or _mail_txt(mail, "k=rsa")
        add(_section("EMAIL SECURITY"))
        add(f"  SPF:   [{'green' if spf else 'yellow'}]"
            f"{'✓ Present' if spf else '⚠ Not found'}[/]")
        add(f"  DKIM:  [{'green' if dkim else 'yellow'}]"
            f"{'✓ Present' if dkim else '⚠ Not found'}[/]")
        if dmarc:
            policy = ""
            for part in dmarc.split(";"):
                if part.strip().startswith("p="):
                    policy = part.strip()[2:].strip().lower()
            pc = "green" if policy in ("reject", "quarantine") else "yellow"
            note = " [dim](monitor only — no enforcement)[/]" if policy == "none" else ""
            add(f"  DMARC: [{pc}]✓ Present[/]  [dim]p={_esc(policy or '?')}[/]{note}")
        else:
            add("  DMARC: [yellow]⚠ Not found[/]")
        if spf:
            add(f"  [dim]{_trunc(spf, 72)}[/]")
        add("")

    # Mixed content & third-party script integrity
    mc = _dict(data.get("mixed-content"))
    if mc:
        add(_section("MIXED CONTENT & SCRIPT INTEGRITY"))
        if _note(mc):
            add(_note(mc))
        else:
            for group in ("active", "passive", "forms"):
                urls = mc.get(group) or []
                c = "red" if urls and group != "passive" else "yellow" if urls else "green"
                add(f"  [{c}]{'⚠' if urls else '✓'}[/] http {group}: [white]{len(urls)}[/]")
                for u in urls[:5]:
                    add(f"      [dim]{_trunc(u, 70)}[/]")
            add(f"  Upgrade-insecure-requests: "
                f"{'[green]✓ set[/]' if mc.get('upgradeInsecureRequests') else '[yellow]not set[/]'}")
            miss = _dict(mc.get("missingIntegrity"))
            n_miss = len(miss.get("versioned") or []) + len(miss.get("unversioned") or [])
            add(f"  Third-party scripts: [white]{mc.get('thirdPartyScripts', 0)}[/]  "
                f"[{'yellow' if n_miss else 'green'}]{n_miss} without SRI[/]")
            for u in (miss.get("versioned") or [])[:5]:
                add(f"      [dim]{_trunc(u, 70)}[/]")
            blocked = mc.get("missingCrossorigin") or []
            if blocked:
                add(f"  [red]⚠ {len(blocked)} hashed script(s) blocked: missing crossorigin[/]")
        add("")

    # Trackers
    tr = _dict(data.get("trackers"))
    if tr:
        add(_section("TRACKERS"))
        found = [t for t in tr.get("trackers") or [] if isinstance(t, dict)]
        if _note(tr):
            add(_note(tr))
        else:
            others = tr.get("otherTrackers") or []
            add(f"  [white]{len(found)}[/] known, [white]{len(others)}[/] other, "
                f"[white]{len(tr.get('unknown') or [])}[/] unknown third-party hosts  "
                f"[dim]({tr.get('requests', 0)} requests)[/]")
            for t in found:
                add(f"  [yellow]■[/] [white]{_trunc(t.get('name', '?'), 30)}[/] "
                    f"[dim]{_trunc(t.get('category', ''), 24)} · {_trunc(t.get('company', ''), 30)}[/]")
            for h in others[:10]:
                add(f"  [dim]■ {_trunc(h, 70)}[/]")
        add("")

    # Data breaches (Have I Been Pwned)
    br = _dict(data.get("breaches"))
    if br:
        add(_section("DATA BREACHES"))
        items = [b for b in br.get("breaches") or [] if isinstance(b, dict)]
        if _note(br):
            add(_note(br))
        elif not items:
            add("  [green]✓ No known breaches[/]")
        else:
            add(f"  [red]⚠ {len(items)} known breach(es)[/]")
            for b in items:
                n = b.get("accounts")
                accts = f"  {n:,} accounts" if isinstance(n, int) else ""
                add(f"  [white]{_trunc(b.get('title') or b.get('name', '?'), 40)}[/] "
                    f"[dim]{_esc(_fmt_date(str(b.get('date', ''))))}{accts}[/]")
                if b.get("exposed"):
                    add(f"      [dim]{_trunc(', '.join(map(str, b['exposed'])), 70)}[/]")
        add("")

    return "\n".join(L)


def tab_dns(data: dict) -> str:
    L: list[str] = []
    add = L.append

    dns = data.get("dns") or {}

    # A / AAAA
    for rtype, label in [("A", "A RECORDS (IPv4)"), ("AAAA", "AAAA RECORDS (IPv6)")]:
        records = dns.get(rtype, [])
        if records:
            add(_section(label))
            for ip in records:
                add(f"  [white]{_esc(str(ip))}[/]")
            add("")

    # MX
    mx_records = [m for m in dns.get("MX", []) if isinstance(m, dict)]
    if mx_records:
        add(_section("MX RECORDS"))
        for mx in sorted(mx_records, key=lambda x: x.get("priority", 0)):
            add(f"  [{mx.get('priority', '?')}] [white]{_esc(str(mx.get('exchange', '')))}[/]")
        add("")

    # NS
    ns_records = dns.get("NS", [])
    if ns_records:
        add(_section("NS RECORDS"))
        for ns in ns_records:
            add(f"  [white]{_esc(str(ns))}[/]")
        add("")

    # CAA (dedicated endpoint; falls back to the generic list below)
    caa = _dict(data.get("caa-records"))
    caa_recs = [r for r in caa.get("records") or [] if isinstance(r, dict)]
    if caa:
        add(_section("CAA RECORDS (CERTIFICATE AUTHORITIES)"))
        if _note(caa):
            add(_note(caa))
        elif not caa_recs:
            add("  [yellow]⚠ None — any CA may issue certificates[/]")
        for r in caa_recs:
            crit = " [red](critical)[/]" if r.get("critical") else ""
            add(f"  [cyan]{_esc(str(r.get('tag', '?')))}[/] [white]{_trunc(r.get('value', ''), 60)}[/]{crit}")
        add("")

    # Simple list record types (CNAME / CAA / SRV / PTR)
    for rtype in ("CNAME", "CAA", "SRV", "PTR"):
        if rtype == "CAA" and caa_recs:
            continue
        records = dns.get(rtype, [])
        if records:
            add(_section(f"{rtype} RECORDS"))
            for r in records:
                add(f"  [white]{_esc(str(r))}[/]")
            add("")

    # SOA
    soa = _dict(dns.get("SOA"))
    if soa:
        add(_section("SOA RECORD"))
        if soa.get("nsname"):
            add(f"  Primary NS:  [white]{_esc(str(soa['nsname']))}[/]")
        if soa.get("hostmaster"):
            add(f"  Hostmaster:  [dim]{_esc(str(soa['hostmaster']))}[/]")
        if soa.get("serial"):
            add(f"  Serial:      [dim]{_esc(str(soa['serial']))}[/]")
        add("")

    # TXT records (parsed)
    txt_parsed = data.get("txt-records") or {}
    if txt_parsed:
        add(_section("TXT RECORDS (PARSED)"))
        for k, v in txt_parsed.items():
            val_str = _trunc(str(v), 72) if v else ""
            if val_str:
                add(f"  [cyan]{_esc(str(k))}:[/] [dim]{val_str}[/]")
            else:
                add(f"  [dim]{_esc(str(k))}[/]")
        add("")

    # Subdomains
    subs_data = data.get("subdomains") or {}
    subs = subs_data.get("subdomains", [])
    if subs:
        count = subs_data.get("count", len(subs))
        source = subs_data.get("source", "")
        truncated = subs_data.get("truncated", False)
        add(_section(f"SUBDOMAINS  ({count}{'+ truncated' if truncated else ''} via {_esc(str(source))})"))
        for s in subs:
            add(f"  [white]{_esc(str(s))}[/]")
        add("")

    # DNS Server
    dns_server = data.get("dns-server") or {}
    if dns_server and not dns_server.get("error"):
        add(_section("DNS SERVER"))
        for k, v in dns_server.items():
            if v is not None:
                add(f"  [cyan]{_esc(str(k))}:[/] [dim]{_trunc(str(v))}[/]")
        add("")

    return "\n".join(L)


def tab_network(data: dict) -> str:
    L: list[str] = []
    add = L.append

    PORT_LABELS: dict[int, str] = {
        20: "FTP Data", 21: "FTP", 22: "SSH", 23: "Telnet",
        25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
        119: "NNTP", 123: "NTP", 143: "IMAP", 179: "BGP",
        194: "IRC", 443: "HTTPS", 587: "SMTP/TLS",
        993: "IMAPS", 995: "POP3S", 3306: "MySQL",
        3389: "RDP", 5060: "SIP", 5900: "VNC",
        8080: "HTTP Alt", 8443: "HTTPS Alt", 8888: "Jupyter",
    }
    RISKY_PORTS = {21, 22, 23, 3306, 3389, 5900}

    ip = _dict(data.get("get-ip"))
    if ip:
        add(_section("RESOLVED IP"))
        if ip.get("ip"):
            fam = f"  [dim]IPv{ip['family']}[/]" if ip.get("family") else ""
            add(f"  [white]{_esc(str(ip['ip']))}[/]{fam}")
        else:
            add(_note(ip) or "  [dim]Unknown[/]")
        add("")

    loc = _dict(data.get("location"))
    if loc:
        add(_section("SERVER LOCATION"))
        if _note(loc):
            add(_note(loc))
        else:
            city = ", ".join(str(loc[k]) for k in ("postal", "city", "region") if loc.get(k))
            cc = str(loc.get("country_code") or "")
            flag = "".join(chr(0x1F1E6 + ord(c) - 65) for c in cc.upper()) \
                if len(cc) == 2 and cc.isascii() and cc.isalpha() else ""
            asn = loc.get("asn")
            rows = (("City", city), ("Country", f"{loc.get('country_name', '')} {flag}".strip()),
                    ("Timezone", loc.get("timezone")), ("Network", loc.get("org")),
                    ("ASN", f"AS{asn}" if asn else ""))
            for label, val in rows:
                if val:
                    add(f"  {label + ':':<10} [white]{_trunc(val, 60)}[/]")
            if loc.get("latitude") is not None and loc.get("longitude") is not None:
                add(f"  [dim]Latitude: {loc['latitude']}, Longitude: {loc['longitude']}[/]")
        add("")

    ports = data.get("ports") or {}
    if ports:
        open_ports = sorted(ports.get("openPorts", []))
        add(_section(f"OPEN PORTS  ({len(open_ports)} open)"))
        if open_ports:
            for p in open_ports:
                label = PORT_LABELS.get(p, "")
                c = "yellow" if p in RISKY_PORTS else "green"
                lbl = f"  [dim]({label})[/]" if label else ""
                add(f"  [{c}]■[/] [white]{p}[/]{lbl}")
        else:
            add("  [dim]None found[/]")
        add("")

    # HTTP headers
    headers = data.get("headers") or {}
    if headers:
        add(_section("HTTP RESPONSE HEADERS"))
        for k, v in sorted(headers.items()):
            add(f"  [cyan]{_esc(str(k))}:[/] [dim]{_trunc(str(v), 72)}[/]")
        add("")

    # Trace route — API returns {"result": [{"<ip>": [rtt_ms, ...]}, ...]}
    trace = data.get("trace-route") or {}
    hops = trace.get("result") or trace.get("hops") or []
    if hops:
        add(_section(f"TRACE ROUTE  ({len(hops)} hops)"))
        for i, hop in enumerate(hops[:30], 1):
            if not isinstance(hop, dict) or not hop:
                continue
            host, rtts = next(iter(hop.items()))
            rtt = f"{min(rtts):.1f} ms" if isinstance(rtts, list) and rtts else ""
            add(f"  {i:>3}  [white]{_esc(str(host))}[/]  [dim]{rtt}[/]")
        add("")

    return "\n".join(L)


def tab_tls(data: dict) -> str:
    L: list[str] = []
    add = L.append

    audit = data.get("tls-security-audit") or {}
    endpoints = audit.get("endpoints") or []

    # SSL-Labs runs async and takes minutes; a live scan often returns before
    # it's READY, leaving no endpoints. Show status so the tab isn't blank.
    if audit and not endpoints:
        add(_section("TLS GRADE"))
        status = audit.get("status") or audit.get("error") or "No data"
        msg = audit.get("statusMessage") or ""
        add(f"  [yellow]⚠ {_esc(str(status))}[/]" +
            (f"  [dim]{_esc(str(msg))}[/]" if msg else ""))
        if str(status).upper() in ("IN_PROGRESS", "DNS", "READY"):
            add("  [dim]SSL-Labs scan not finished — re-scan in a few minutes.[/]")
        add("")

    VULN_KEYS = [
        ("vulnBeast",         "BEAST"),
        ("heartbleed",        "Heartbleed"),
        ("poodle",            "POODLE"),
        ("freak",             "FREAK"),
        ("logjam",            "Logjam"),
        ("drownVulnerable",   "DROWN"),
        ("ticketbleed",       "Ticketbleed"),
        ("bleichenbacher",    "Bleichenbacher"),
        ("zombiePoodle",      "Zombie POODLE"),
        ("goldenDoodle",      "Golden Doodle"),
    ]

    def _signature(ep: dict) -> tuple:
        """Fingerprint the fields we display, so IPs with an identical TLS
        config collapse into one block (common behind a CDN/anycast)."""
        d = ep.get("details") or {}
        suites = tuple(
            s.get("name")
            for g in (d.get("suites") or [])
            for s in (g.get("list") or [])
        )
        protos = tuple((p.get("name"), p.get("version")) for p in (d.get("protocols") or []))
        vulns = tuple(d.get(k) for k, _ in VULN_KEYS)
        fails = tuple(sorted(
            f"{(s.get('client') or {}).get('name')}/{(s.get('client') or {}).get('version')}"
            for s in ((d.get("sims") or {}).get("results") or []) if s.get("errorCode")
        ))
        return (ep.get("grade"), ep.get("hasWarnings"), protos, suites,
                vulns, d.get("ocspStapling"), fails)

    # Collapse endpoints that share an identical config, preserving first-seen order
    groups: dict[tuple, list] = {}
    for ep in endpoints:
        groups.setdefault(_signature(ep), []).append(ep)

    for eps in groups.values():
        ep = eps[0]
        ips = [_esc(str(e.get("ipAddress", "?"))) for e in eps]
        grade = _esc(str(ep.get("grade") or "N/A"))
        gc = _grade_color(ep.get("grade") or "")
        warn_str = "  [yellow]⚠ Warnings[/]" if ep.get("hasWarnings") else ""
        add(_section(f"TLS GRADE — {ips[0]}"))
        add(f"  [{gc}]{grade}[/]{warn_str}")
        if len(ips) > 1:
            add(f"  [dim]+{len(ips) - 1} more IP(s) with identical config: "
                f"{', '.join(ips[1:])}[/]")
        add("")

        details = ep.get("details") or {}
        if not details:
            continue

        # Protocols
        protocols = details.get("protocols") or []
        if protocols:
            add("  [bold]Supported protocols:[/]")
            for proto in protocols:
                name = proto.get("name", "")
                ver = proto.get("version", "")
                en, ev = _esc(str(name)), _esc(str(ver))
                if name == "SSL" or (name == "TLS" and ver in ("1.0", "1.1")):
                    add(f"    [yellow]⚠ {en} {ev} [dim](deprecated/insecure)[/][/]")
                else:
                    add(f"    [green]✓ {en} {ev}[/]")
            add("")

        # Cipher suites
        suites_data = details.get("suites") or []
        if suites_data:
            # suites may be a list of suite-group objects
            add("  [bold]Cipher suites:[/]")
            shown = 0
            for suite_group in suites_data:
                for suite in (suite_group.get("list") or []):
                    name = suite.get("name") or ""
                    if name:
                        add(f"    [dim]{_esc(str(name))}[/]")
                        shown += 1
                    if shown >= 8:
                        break
                if shown >= 8:
                    break
            add("")

        # Vulnerabilities
        vuln_found = []
        vuln_safe = []
        for key, label in VULN_KEYS:
            val = details.get(key)
            if val is True or (isinstance(val, int) and val > 0):
                vuln_found.append(label)
            elif val is False or val == 0:
                vuln_safe.append(label)

        if vuln_found or vuln_safe:
            add("  [bold]Vulnerability checks:[/]")
            for label in vuln_found:
                add(f"    [red]✗ {label}: Vulnerable[/]")
            for label in vuln_safe:
                add(f"    [green]✓ {label}: Not vulnerable[/]")
            add("")

        # Handshake simulation — which clients can negotiate a connection
        sims = (details.get("sims") or {}).get("results") or []
        if sims:
            failed = [s for s in sims if s.get("errorCode")]
            add("  [bold]Handshake simulation:[/]")
            add(f"    [green]✓ {len(sims) - len(failed)} clients connected[/]"
                f"   [{'red' if failed else 'green'}]"
                f"{'✗' if failed else '✓'} {len(failed)} failed[/]")
            for s in failed[:12]:
                c = s.get("client") or {}
                ver = _esc(str(c.get("version") or ""))
                add(f"    [red]✗ {_esc(str(c.get('name', '?')))} {ver}[/]")
            add("")

        # Extra details
        ocsp = details.get("ocspStapling", False)
        add(f"  OCSP Stapling: [{'green' if ocsp else 'yellow'}]{'Enabled' if ocsp else 'Disabled'}[/]")
        http_status = details.get("httpStatusCode")
        if http_status:
            add(f"  HTTP status:   [dim]{http_status}[/]")
        add("")

    # TLS connection info
    tls_conn = data.get("tls-connection") or {}
    if tls_conn and not tls_conn.get("error"):
        add(_section("TLS CONNECTION"))
        for k, v in tls_conn.items():
            if v is not None and k != "error":
                add(f"  [cyan]{_esc(str(k))}:[/] [dim]{_trunc(str(v))}[/]")
        add("")

    return "\n".join(L)


def tab_tech(data: dict) -> str:
    L: list[str] = []
    add = L.append

    # Tech stack
    tech_stack = data.get("tech-stack") or {}
    technologies = tech_stack.get("technologies") or []
    if technologies:
        # Group by first category
        by_cat: dict[str, list] = {}
        for tech in technologies:
            if not isinstance(tech, dict):
                continue
            cats = tech.get("categories") or []
            cat_name = cats[0].get("name", "Other") if cats and isinstance(cats[0], dict) else "Other"
            by_cat.setdefault(cat_name, []).append(tech)

        add(_section(f"TECHNOLOGY STACK  ({len(technologies)} detected)"))
        for cat, techs in sorted(by_cat.items()):
            add(f"  [bold yellow]{_esc(str(cat))}[/]")
            for t in techs:
                name = _esc(str(t.get("name", "")))
                ver = _esc(str(t.get("version") or ""))
                conf = t.get("confidence", 100)
                ver_str = f" [dim]{ver}[/]" if ver else ""
                conf_str = f" [dim]({conf}%)[/]" if conf < 100 else ""
                add(f"    [white]{name}[/]{ver_str}{conf_str}")
        add("")

    # Mail config (MX + provider; SPF/DKIM/DMARC live in the Security tab)
    mail = data.get("mail-config") or {}
    if mail:
        add(_section("MAIL CONFIGURATION"))

        for mx in (mail.get("mxRecords") or []):
            if not isinstance(mx, dict):
                continue
            prio = mx.get("priority", "")
            exch = _esc(str(mx.get("exchange", "")))
            add(f"  MX [{prio}] [white]{exch}[/]")

        svcs = mail.get("mailServices") or []
        if svcs:
            add("  [bold]Mail services:[/]")
            for svc in svcs:
                if isinstance(svc, dict):
                    n = svc.get("provider") or svc.get("name") or svc.get("value") or "?"
                else:
                    n = svc
                add(f"    [cyan]{_esc(str(n))}[/]")
        add("  [dim]SPF / DKIM / DMARC → Security tab[/]")
        add("")

    # Linked pages
    lp = data.get("linked-pages") or {}
    internal = lp.get("internal") or []
    external = lp.get("external") or []
    if internal or external:
        add(_section(f"LINKED PAGES  ({len(internal)} internal, {len(external)} external)"))
        if external:
            add("  [bold]External:[/]")
            for u in external[:15]:
                add(f"    [white]{_trunc(u, 70)}[/]")
        if internal:
            add("  [bold]Internal:[/]")
            for u in internal[:10]:
                add(f"    [dim]{_trunc(u, 70)}[/]")
            if len(internal) > 10:
                add(f"    [dim]… +{len(internal) - 10} more[/]")
        add("")

    # Robots.txt
    robots = data.get("robots-txt") or {}
    if robots:
        present = robots.get("isPresent", False) or bool(robots.get("content"))
        add(_section("ROBOTS.TXT"))
        c = "green" if present else "yellow"
        add(f"  [{c}]{'Present' if present else 'Not found'}[/]")
        content = robots.get("content") or ""
        if content:
            for line in content.splitlines()[:20]:
                if line.strip():
                    add(f"  [dim]{_esc(line)}[/]")
        add("")

    # Sitemap
    sitemap = data.get("sitemap") or {}
    if sitemap:
        present = sitemap.get("isFound", False) or bool(sitemap.get("url"))
        url = _esc(str(sitemap.get("url") or ""))
        add(_section("SITEMAP"))
        c = "green" if present else "yellow"
        add(f"  [{c}]{'Present' if present else 'Not found'}[/]")
        if url:
            add(f"  [dim]{url}[/]")
        add("")

    # Archives
    archives = data.get("archives") or {}
    count = archives.get("totalResults") or archives.get("count") or 0
    first_seen = _esc(str(archives.get("firstSeen") or archives.get("oldest") or ""))
    last_seen = _esc(str(archives.get("lastSeen") or archives.get("newest") or ""))
    if count or first_seen:
        add(_section("WEB ARCHIVES"))
        if count:
            add(f"  Snapshots:  [white]{count:,}[/]")
        if first_seen:
            add(f"  First seen: [dim]{first_seen}[/]")
        if last_seen:
            add(f"  Last seen:  [dim]{last_seen}[/]")
        add("")

    return "\n".join(L)


def tab_raw(data: dict) -> RichText:
    """Return plain (non-markup) Rich Text so JSON brackets aren't parsed."""
    return RichText(json.dumps(data, indent=2, default=str))


# ═══════════════════════════════════════════════════════════════
#  Screens
# ═══════════════════════════════════════════════════════════════

class FilePickerScreen(Screen):
    """Initial screen: select a JSON file from the results directory."""

    BINDINGS = [
        Binding("q", "app.quit", "Quit"),
        Binding("escape", "app.quit", "Quit"),
    ]

    DEFAULT_CSS = """
    FilePickerScreen {
        background: $surface;
    }
    #picker-intro {
        margin: 1 2;
        color: $text-muted;
    }
    #file-list {
        margin: 0 2;
        height: 1fr;
    }
    .empty-msg {
        margin: 2 4;
        color: $warning;
    }
    """

    def __init__(self, results_dir: Path, **kwargs):
        super().__init__(**kwargs)
        self.results_dir = results_dir
        self.json_files: list[Path] = sorted(results_dir.glob("*.json"))

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield Label(
            f"Results folder: [dim]{self.results_dir}[/]  —  "
            f"Press [bold]Enter[/] to open, [bold]q[/] to quit",
            id="picker-intro",
        )
        if self.json_files:
            items = [ListItem(Label(f.name)) for f in self.json_files]
            yield ListView(*items, id="file-list")
        else:
            yield Label(
                f"No JSON files found in [bold]{self.results_dir}[/].\n"
                "Place web-check result files there and restart.",
                classes="empty-msg",
            )
        yield Footer()

    @on(ListView.Selected)
    def file_selected(self, event: ListView.Selected) -> None:
        idx = event.list_view.index
        if idx is not None:
            self.app.push_screen(MainScreen(self.json_files[idx]))


class MainScreen(Screen):
    """Main viewer screen with tabbed sections."""

    BINDINGS = [
        Binding("o", "open_picker", "Open file", show=True),
        Binding("s", "save_scan", "Save", show=True),
        Binding("q", "app.quit", "Quit", show=True),
        Binding("escape", "go_back", "Back", show=True),
    ]

    DEFAULT_CSS = """
    MainScreen {
        background: $surface;
    }
    #domain-header {
        background: $panel;
        padding: 0 2;
        height: 1;
        color: $accent;
        text-style: bold;
    }
    TabbedContent {
        height: 1fr;
    }
    TabPane {
        padding: 0;
    }
    VerticalScroll {
        padding: 1 3;
    }
    Static.content {
        width: 100%;
    }
    """

    def __init__(self, json_path: Optional[Path] = None,
                 data: Optional[dict] = None, title: str = "", **kwargs):
        super().__init__(**kwargs)
        self.json_path = json_path          # None in live mode
        self.data: dict = data or {}
        self._preloaded = data is not None   # live scan, already in memory
        self._title = title

    def on_mount(self) -> None:
        if not self._preloaded:
            try:
                with open(self.json_path) as f:
                    self.data = json.load(f)
            except Exception as e:
                self.data = {}
                self.notify(f"Error loading {self.json_path.name}: {e}", severity="error")
                return

        # Build domain label
        domain_name = (
            (self.data.get("domain") or {}).get("domain")
            or (self.data.get("whois") or {}).get("domain")
            or self._title
            or (self.json_path.stem if self.json_path else "Scan")
        )
        source = self._title if self._preloaded else self.json_path.name
        status = self.data.get("status") or {}
        is_up = status.get("isUp", False)
        status_str = " ✓" if is_up else " ✗"
        self.query_one("#domain-header", Static).update(
            f"{domain_name}{status_str}  —  {source}"
        )

        # Populate tab content
        tab_builders = {
            "advisories": tab_advisories,
            "overview":  tab_overview,
            "security":  tab_security,
            "dns":       tab_dns,
            "network":   tab_network,
            "tls":       tab_tls,
            "tech":      tab_tech,
            "raw":       tab_raw,
        }
        for tab_id, builder in tab_builders.items():
            widget = self.query_one(f"#content-{tab_id}", Static)
            try:
                content = builder(self.data)
                widget.update(content)  # markup is parsed here — can raise
            except Exception as e:
                # Never let one tab's bad data crash the whole app
                widget.update(RichText(f"Error rendering tab: {e}"))

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("Loading…", id="domain-header")
        with TabbedContent():
            tab_defs = [
                ("Advisories", "advisories"),
                ("Overview", "overview"),
                ("Security", "security"),
                ("DNS",      "dns"),
                ("Network",  "network"),
                ("TLS",      "tls"),
                ("Tech",     "tech"),
                ("Raw JSON", "raw"),
            ]
            for label, tab_id in tab_defs:
                with TabPane(label, id=f"tab-{tab_id}"):
                    with VerticalScroll():
                        yield Static("", id=f"content-{tab_id}", classes="content", markup=True)
        yield Footer()

    def action_open_picker(self) -> None:
        # Live scan has no source file, so browse the default results/ folder
        # (the same dir `save` writes to).
        folder = (self.json_path.parent if self.json_path is not None
                  else Path(__file__).resolve().parent / "results")
        folder.mkdir(parents=True, exist_ok=True)
        self.app.push_screen(FilePickerScreen(folder))

    def action_save_scan(self) -> None:
        if self.json_path is not None:
            self.notify("Already loaded from a file — nothing to save.",
                        severity="warning")
            return
        out_dir = Path(__file__).resolve().parent / "results"
        out_dir.mkdir(parents=True, exist_ok=True)
        out = out_dir / f"{_safe_filename(self._title)}.json"
        try:
            out.write_text(json.dumps(self.data, indent=2, default=str))
        except Exception as e:
            self.notify(f"Save failed: {e}", severity="error")
            return
        self.notify(f"Saved to {out}", severity="information")

    def action_go_back(self) -> None:
        # Only pop when a real picker is underneath; the bottom of the stack is
        # Textual's blank default screen — popping to it strands the user.
        below = self.app.screen_stack[-2] if len(self.app.screen_stack) > 1 else None
        if isinstance(below, FilePickerScreen):
            self.app.pop_screen()
        elif self.json_path is not None:
            # launched with a direct file: open its folder to browse siblings
            self.app.push_screen(FilePickerScreen(self.json_path.parent))
        else:
            # live scan: nothing behind us, so esc backs all the way out
            self.app.exit()


# ═══════════════════════════════════════════════════════════════
#  App
# ═══════════════════════════════════════════════════════════════

class WebCheckApp(App):
    TITLE = "Web Check TUI"
    BINDINGS = [Binding("q", "quit", "Quit")]

    def __init__(self, initial_file: Optional[Path], results_dir: Path,
                 live_data: Optional[dict] = None, live_title: str = "", **kwargs):
        super().__init__(**kwargs)
        self.initial_file = initial_file
        self.results_dir = results_dir
        self.live_data = live_data
        self.live_title = live_title

    def on_mount(self) -> None:
        if self.live_data is not None:
            self.push_screen(MainScreen(data=self.live_data, title=self.live_title))
        elif self.initial_file:
            self.push_screen(MainScreen(self.initial_file))
        else:
            self.push_screen(FilePickerScreen(self.results_dir))

    def get_system_commands(self, screen):
        # Drop the built-in "Save screenshot" palette entry — it writes an SVG
        # with no feedback, which reads as broken. Keep everything else.
        for cmd in super().get_system_commands(screen):
            if "screenshot" not in cmd.title.lower():
                yield cmd


# ═══════════════════════════════════════════════════════════════
#  Entry point
# ═══════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Terminal viewer for web-check JSON results.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s                          # browse ./results/ folder\n"
            "  %(prog)s results/example.com.json # open specific file\n"
            "  %(prog)s --dir ~/web-checks       # specify results directory\n"
        ),
    )
    parser.add_argument("file", nargs="?", help="Path to a web-check JSON file")
    parser.add_argument(
        "--dir", "-d",
        default=None,
        help="Directory containing JSON result files (default: ./results/)",
    )
    parser.add_argument(
        "--scan", "-s", metavar="URL",
        help="Live-scan a site via a web-check API instead of reading a file",
    )
    parser.add_argument(
        "--api",
        default="http://localhost:3000",
        help="Base URL of the web-check instance (default: %(default)s). "
             "Self-host with: docker run -p 3000:3000 lissy93/web-check",
    )
    parser.add_argument(
        "--save", metavar="PATH",
        help="With --scan, also write the fetched results to this JSON file",
    )
    args = parser.parse_args()

    # Live scan: fetch from the API, then launch straight into the viewer
    if args.scan:
        def _progress(done: int, total: int, key: str) -> None:
            print(f"\r  scanning… {done:>2}/{total}  ({key})".ljust(50),
                  end="", file=sys.stderr, flush=True)

        print(f"Scanning {args.scan} via {args.api} …", file=sys.stderr)
        data = fetch_live(args.scan, args.api, progress=_progress)
        print("", file=sys.stderr)
        if all(isinstance(v, dict) and v.get("error") for v in data.values()):
            print(f"Error: no checks succeeded. Is web-check running at {args.api}?",
                  file=sys.stderr)
            sys.exit(1)
        if args.save:
            Path(args.save).expanduser().write_text(json.dumps(data, indent=2, default=str))
        WebCheckApp(initial_file=None, results_dir=Path.cwd(),
                    live_data=data, live_title=args.scan).run()
        return

    # Resolve results directory
    if args.dir:
        results_dir = Path(args.dir).expanduser().resolve()
    else:
        results_dir = Path(__file__).parent / "results"

    if not results_dir.exists():
        results_dir.mkdir(parents=True, exist_ok=True)

    # Resolve specific file
    initial_file: Optional[Path] = None
    if args.file:
        p = Path(args.file).expanduser().resolve()
        if not p.exists():
            print(f"Error: file not found: {p}", file=sys.stderr)
            sys.exit(1)
        if not p.suffix == ".json":
            print(f"Warning: {p.name} does not look like a JSON file", file=sys.stderr)
        initial_file = p

    WebCheckApp(initial_file=initial_file, results_dir=results_dir).run()


if __name__ == "__main__":
    main()
