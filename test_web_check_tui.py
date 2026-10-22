"""Minimal self-check for live-fetch wiring. Run: python test_web_check_tui.py"""
from textual.content import Content  # the parser Static.update actually uses
import web_check_tui as w
from web_check_tui import _build_api_url, _safe_filename, LIVE_ENDPOINTS


def _parse(markup: str) -> None:
    # Validate with Textual's markup parser (stricter than rich's), since that's
    # what renders the tabs. rich.text.Text.from_markup is too lenient and misses
    # unclosed-bracket failures like '[expires=...'.
    Content.from_markup(markup)


def test_markup_safe_against_hostile_data():
    # Scan data is untrusted: any field may contain '[' that breaks Rich markup.
    # The trace-route list value is the one that actually crashed in the wild.
    # Include the real-world breakers: an UNCLOSED tag-like bracket (rich.escape
    # leaves it alone, Textual rejects it) and dict fields that arrive as strings.
    evil = "x [expires=-1782755345.804364, weight=10, ttl=3600, region=us-east-1"
    data = {
        "domain": {"domain": evil, "registrar": evil, "nameservers": [evil]},
        "redirects": {"redirects": [evil]},
        "rank": {"ranks": [{"rank": 1, "date": evil}]},
        "social-tags": {"title": evil, "ogType": evil},
        # issuer/subject as STRINGS (real APIs do this) — must not crash
        "ssl": {"isValid": True, "issuer": evil, "subject": evil,
                "valid_from": evil, "valid_to": evil, "serialNumber": evil},
        "hsts": {"hstsHeader": evil},
        "firewall": {"hasWaf": True, "waf": evil},
        # stray string elements mixed into lists-of-dicts must be skipped, not crash
        "block-lists": {"blocklists": [{"server": evil, "isBlocked": True}, evil]},
        "cookies": {"headerCookies": [{"name": evil, "sameSite": evil}, evil]},
        "dns": {"A": [evil], "MX": [{"exchange": evil}, evil], "NS": [evil], "CAA": [evil]},
        "txt-records": {evil: evil},
        "subdomains": {"subdomains": [evil], "source": evil},
        "dns-server": {evil: evil},
        "headers": {evil: evil},
        "trace-route": {"hops": [{"hop": 1, "host": evil, "rtt": [-1782754643.92]}, evil]},
        "tls-security-audit": {"endpoints": [{"ipAddress": evil, "grade": "B",
            "details": {"protocols": [{"name": evil, "version": evil}],
                        "suites": [{"list": [{"name": evil}]}],
                        "sims": {"results": [{"errorCode": 1, "client": {"name": evil, "version": evil}}]}}}]},
        "tls-connection": {evil: evil},
        "tech-stack": {"technologies": [{"name": evil, "categories": [{"name": evil}]}, evil]},
        "mail-config": {"mxRecords": [{"exchange": evil}], "mailServices": [{"provider": evil}],
                        "txtRecords": [["v=spf1 " + evil], ["v=DMARC1; p=none;"]]},
        "robots-txt": {"content": f"User-agent: {evil}"},
        "sitemap": {"url": evil},
        "archives": {"count": 3, "firstSeen": evil, "lastSeen": evil},
        "caa-records": {"records": [{"tag": evil, "value": evil, "critical": True}, evil]},
        "mixed-content": {"active": [evil], "passive": [evil], "forms": [evil],
                          "upgradeInsecureRequests": False, "thirdPartyScripts": 2,
                          "missingIntegrity": {"versioned": [evil], "unversioned": [evil]},
                          "missingCrossorigin": [evil]},
        "trackers": {"requests": 4, "trackers": [{"name": evil, "category": evil, "company": evil}, evil],
                     "otherTrackers": [evil], "unknown": [evil]},
        "social-presence": {"profiles": [{"network": evil, "handle": evil, "followers": 5}, evil]},
        "location": {"city": evil, "country_name": evil, "org": evil, "latitude": 1, "longitude": 2},
        "get-ip": {"ip": evil, "family": 4},
        "breaches": {"breaches": [{"title": evil, "date": evil, "accounts": 9, "exposed": [evil]}, evil]},
    }
    for fn in (w.tab_advisories, w.tab_overview, w.tab_security, w.tab_dns, w.tab_network,
               w.tab_tls, w.tab_tech):
        _parse(fn(data))  # raises if a bracket leaked or a string crashed a builder


def test_advisories_severity_and_order():
    from advisories import analyze
    f = analyze({"hsts": {}, "ports": {"openPorts": [23, 25, 443]}, "firewall": {"hasWaf": True, "waf": "X"},
                 "status": {"error": "boom"}, "threats": "not a dict"})
    sev = [x[0] for x in f]
    assert sev == sorted(sev, key=["critical", "issue", "warning", "info", "pass"].index), sev
    assert ("critical", "ports") == f[0][:2] and ("pass", "firewall") == f[-1][:2], f
    assert not any(x[1] in ("status", "threats") for x in f)  # errored/garbage checks skipped


def test_safe_filename():
    assert _safe_filename("https://example.com/") == "example.com"
    assert _safe_filename("sub.example.co.uk") == "sub.example.co.uk"
    assert _safe_filename("http://a/b?c=1") == "a_b_c_1"
    assert _safe_filename("") == "scan"


def test_build_api_url():
    u = _build_api_url("http://localhost:3000/", "ssl", "https://example.com")
    assert u == "http://localhost:3000/api/ssl?url=https%3A%2F%2Fexample.com", u
    # bare domain encodes fine; trailing slash on base is trimmed
    assert "//api" not in u.replace("http://", "")


def test_endpoint_map_covers_rendered_keys():
    # keys the TUI renderers read must each have a live source
    rendered = {
        "whois", "status", "redirects", "rank", "firewall", "social-tags", "carbon",
        "ssl", "hsts", "dnssec", "http-security", "security-txt", "threats",
        "block-lists", "dns", "txt-records", "subdomains", "dns-server", "ports",
        "headers", "cookies", "trace-route", "tls-security-audit", "tls-connection",
        "tech-stack", "mail-config", "robots-txt", "sitemap", "archives",
        "linked-pages", "caa-records", "mixed-content", "trackers",
        "social-presence", "location", "get-ip", "breaches",
    }
    missing = rendered - LIVE_ENDPOINTS.keys()
    assert not missing, f"no live endpoint for: {missing}"


if __name__ == "__main__":
    test_build_api_url()
    test_advisories_severity_and_order()
    test_safe_filename()
    test_endpoint_map_covers_rendered_keys()
    test_markup_safe_against_hostile_data()
    print("ok")
