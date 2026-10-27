"""Advisories: a Python port of web-check's client-side analysis rules
(src/client/analysis/rules/*.ts in https://github.com/Lissy93/web-check).

Each rule takes one check's raw data and returns [(severity, title, detail)].
``analyze(data)`` runs them all over a scan and returns findings as
(severity, check, title, detail), most severe first.

Not ported: ``quality`` (needs a Google API key the TUI doesn't fetch).
"""

import re
from datetime import datetime, timezone
from typing import Callable, Optional

SEVERITIES = ("critical", "issue", "warning", "info", "pass")

Result = tuple  # (severity, title, detail)


def _r(sev: str, title: str, detail: str = "") -> Result:
    return (sev, title, detail)


def _days_until(raw) -> Optional[int]:
    """Whole days until an ISO or OpenSSL-style date, None if unparseable."""
    if not isinstance(raw, str):
        return None
    for parse in (
        lambda s: datetime.fromisoformat(s.replace("Z", "+00:00")),
        lambda s: datetime.strptime(s.strip(), "%b %d %H:%M:%S %Y %Z"),
    ):
        try:
            dt = parse(raw)
        except ValueError:
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (dt - datetime.now(timezone.utc)).days
    return None


def _hosts(urls) -> str:
    out = []
    for u in urls:
        h = re.sub(r"^[a-z]+://", "", str(u)).split("/")[0]
        if h not in out:
            out.append(h)
    return ", ".join(out)


# ── Security headers ───────────────────────────────────────────

_CRITICAL = {
    "contentSecurityPolicy": "Content-Security-Policy",
    "strictTransportPolicy": "Strict-Transport-Security",
    "xContentTypeOptions": "X-Content-Type-Options",
    "xFrameOptions": "X-Frame-Options",
}
_RECOMMENDED = {
    "referrerPolicy": "Referrer-Policy",
    "permissionsPolicy": "Permissions-Policy",
    "crossOriginOpenerPolicy": "Cross-Origin-Opener-Policy",
    "crossOriginResourcePolicy": "Cross-Origin-Resource-Policy",
    "crossOriginEmbedderPolicy": "Cross-Origin-Embedder-Policy",
}
_HEADERS = {**_CRITICAL, **_RECOMMENDED, "xXSSProtection": "X-XSS-Protection"}
_ANY_SOURCE = ("*", "http:", "https:", "data:")


def _parse_csp(header: str) -> list[dict]:
    policies = []
    for policy in header.split(","):
        d = {}
        for directive in policy.split(";"):
            name, *sources = directive.strip().lower().split()
            d[name] = sources
        policies.append(d)
    return policies


def _check_csp(header: str) -> list[Result]:
    policies = _parse_csp(header)
    scripts = [p.get("script-src") or p.get("default-src") for p in policies]
    if all(s is None for s in scripts):
        return [_r("warning", "Content-Security-Policy doesn't restrict scripts",
                   "Add script-src or default-src, so the policy can block injected scripts")]

    def allows(test) -> bool:
        return all(s is None or test(s) for s in scripts)

    out = []
    nonced = lambda s: any(re.match(r"^'(nonce|sha\d+)-", x) for x in s)
    if allows(lambda s: "'unsafe-inline'" in s and not nonced(s)):
        out.append(_r("warning", "Content-Security-Policy allows inline scripts",
                      "'unsafe-inline' lets injected scripts run. Use nonces or hashes instead"))
    if allows(lambda s: any(x in _ANY_SOURCE for x in s) and "'strict-dynamic'" not in s):
        out.append(_r("warning", "Content-Security-Policy allows scripts from any source",
                      "Replace *, http:, https: or data: in script-src with the hosts you load from"))
    if allows(lambda s: "'unsafe-eval'" in s):
        out.append(_r("info", "Content-Security-Policy allows eval()",
                      "'unsafe-eval' lets scripts run text as code, so injected text can run too"))
    unset = [n for n in ("object-src", "base-uri")
             if not any(p.get(n) or (n == "object-src" and p.get("default-src")) for p in policies)]
    if unset:
        out.append(_r("info", f"Content-Security-Policy doesn't set {' or '.join(unset)}",
                      "object-src 'none' blocks plugins, and base-uri 'self' stops injected <base> tags"))
    return out


def _bad_value(label: str, value: str, detail: str) -> list[Result]:
    return [_r("issue", f'{label} is "{value}"', detail)]


def _check_value(key: str, value: str) -> list[Result]:
    if key == "contentSecurityPolicy":
        return _check_csp(value)
    if key == "strictTransportPolicy":
        m = re.search(r'max-age\s*=\s*"?(\d+)', value, re.I)
        if m and int(m.group(1)) > 0:
            return []
        return _bad_value("Strict-Transport-Security", value,
                          "Browsers keep to HTTPS for max-age seconds, so 0 or no max-age turns HSTS off")
    if key == "xContentTypeOptions":
        if re.match(r"^\s*nosniff\s*(,|$)", value, re.I):
            return []
        return _bad_value("X-Content-Type-Options", value,
                          "nosniff is the only valid value, browsers ignore anything else")
    if key == "xFrameOptions":
        if any(re.fullmatch(r"\s*(deny|sameorigin)\s*", o, re.I) for o in value.split(",")):
            return []
        return _bad_value("X-Frame-Options", value,
                          "Only DENY and SAMEORIGIN work, browsers ignore anything else")
    if key == "referrerPolicy":
        if value.split(",")[-1].strip().lower() in ("unsafe-url", "no-referrer-when-downgrade"):
            return [_r("warning", f'Referrer-Policy "{value}" sends full URLs to other sites',
                       "Paths and query strings leak to every site linked or loaded from the page")]
        return []
    if key == "xXSSProtection":
        if value.strip().startswith("0"):
            return []
        return [_r("info", "X-XSS-Protection is turned on",
                   "Browsers dropped this filter, and it made old ones less safe. Set it to 0")]
    return []


def http_security(d: dict) -> list[Result]:
    out = []
    for key, label in _HEADERS.items():
        csp = d.get("contentSecurityPolicy")
        if key == "xFrameOptions" and isinstance(csp, str) and \
                any("frame-ancestors" in p for p in _parse_csp(csp)):
            out.append(_r("pass", "Framing limited by CSP frame-ancestors"))
            continue
        val = d.get(key)
        if val:
            # Older web-check versions return a bare true/false, not the header value
            problems = _check_value(key, val) if isinstance(val, str) else []
            if key in _CRITICAL and all(p[0] == "info" for p in problems):
                out.append(_r("pass", f"{label} set"))
            out += problems
        elif key in _CRITICAL:
            out.append(_r("issue", f"Missing {label}", f"Set the {label} response header"))
        elif key in _RECOMMENDED:
            out.append(_r("warning", f"Missing {label}", f"Consider adding the {label} response header"))
    return out


def mixed_content(d: dict) -> list[Result]:
    if not isinstance(d.get("missingCrossorigin"), list):
        return []
    out = []
    active, passive, forms = (d.get(k) or [] for k in ("active", "passive", "forms"))
    count = len(active) + len(passive) + len(forms)
    if str(d.get("url", "")).startswith("https:"):
        if not count:
            out.append(_r("pass", "No mixed content in the page HTML"))
        elif d.get("upgradeInsecureRequests"):
            out.append(_r("info", f"CSP upgrades {count} HTTP URL(s) to HTTPS",
                          "upgrade-insecure-requests is set, so these only load if the host supports HTTPS"))
        else:
            if active:
                out.append(_r("issue", f"Loads {len(active)} script(s), style(s) or frame(s) over HTTP",
                              f"Browsers block these, which can break the page. From {_hosts(active)}"))
            if passive:
                out.append(_r("warning", f"Loads {len(passive)} image(s) or media file(s) over HTTP",
                              f"Browsers upgrade or block these, old ones load them insecurely. From {_hosts(passive)}"))
            if forms:
                out.append(_r("issue", f"{len(forms)} form(s) submit over HTTP",
                              f"Anything entered is sent unencrypted, to {_hosts(forms)}"))
    miss = d.get("missingIntegrity") or {}
    versioned, unversioned = miss.get("versioned") or [], miss.get("unversioned") or []
    blocked = d.get("missingCrossorigin") or []
    unhashed = versioned + unversioned
    if d.get("integrityPolicy"):
        out.append(_r("issue", f"Integrity-Policy blocks {len(unhashed)} third-party script(s)",
                      f"They have no SRI hash, so browsers won't run them. From {_hosts(unhashed)}")
                   if unhashed else _r("pass", "Integrity-Policy requires SRI on every script"))
    else:
        if versioned:
            out.append(_r("warning", f"{len(versioned)} versioned third-party script(s) without SRI",
                          f"Fixed files can take a hash, to stop tampered copies. From {_hosts(versioned)}"))
        if unversioned:
            out.append(_r("info", f"{len(unversioned)} unversioned third-party script(s) without SRI",
                          f"These can change without notice, so SRI would break them. From {_hosts(unversioned)}"))
        if not unhashed and not blocked and (d.get("thirdPartyScripts") or 0) > 0:
            out.append(_r("pass", f"All {d['thirdPartyScripts']} third-party script(s) use SRI"))
    if blocked:
        out.append(_r("issue", f"{len(blocked)} script(s) with SRI blocked for missing crossorigin",
                      f"Browsers need CORS to check the hash, so won't run these. From {_hosts(blocked)}"))
    return out


def hsts(d: dict) -> list[Result]:
    header = d.get("hstsHeader")
    if not header:
        return [_r("issue", "No HSTS header", "Add Strict-Transport-Security to enforce HTTPS for clients")]
    low = str(header).lower()
    m = re.search(r'max-age\s*=\s*"?(\d+)', low)
    max_age = int(m.group(1)) if m else 0
    out = []
    if max_age < 31536000:
        out.append(_r("warning", "HSTS max-age under a year",
                      f"Current max-age is {max_age}, raise it to 31536000 for preload eligibility"))
    if "includesubdomains" not in low:
        out.append(_r("warning", "HSTS missing includeSubDomains",
                      "Add includeSubDomains to protect every subdomain"))
    if "preload" not in low:
        out.append(_r("info", "HSTS missing preload directive",
                      "Add preload to qualify for the HSTS preload list"))
    if d.get("compatible"):
        out.append(_r("pass", "HSTS preload compatible"))
    return out


_SSL_REASONS = {
    "UNABLE_TO_VERIFY_LEAF_SIGNATURE": "Server doesn't send its intermediate certificate",
    "UNABLE_TO_GET_ISSUER_CERT_LOCALLY": "Server doesn't send its intermediate certificate",
    "DEPTH_ZERO_SELF_SIGNED_CERT": "Self-signed, not issued by a trusted authority",
    "SELF_SIGNED_CERT_IN_CHAIN": "Chain ends at a root browsers don't trust",
    "ERR_TLS_CERT_ALTNAME_INVALID": "Certificate doesn't cover this hostname",
}


def ssl(d: dict) -> list[Result]:
    out = []
    if d.get("isValid") is False:
        err = d.get("authError")
        out.append(_r("critical", "SSL certificate invalid",
                      _SSL_REASONS.get(err) or err or "Certificate failed validation"))
    elif d.get("isValid") is True:
        out.append(_r("pass", "SSL certificate valid"))
    days = _days_until(d.get("valid_to"))
    if days is not None and days <= 30:
        if days < 0:
            out.append(_r("critical", "SSL certificate expired", f"Expired {-days} day(s) ago"))
        elif days <= 7:
            out.append(_r("critical", "SSL certificate expiring within a week",
                          f"Expires in {days} day(s), renew immediately"))
        elif days <= 14:
            out.append(_r("issue", "SSL certificate expiring soon",
                          f"Expires in {days} day(s), schedule renewal"))
        else:
            out.append(_r("warning", "SSL certificate renews within a month", f"Expires in {days} day(s)"))
    return out


def tls_connection(d: dict) -> list[Result]:
    out = []
    protocol = str(d.get("protocol") or "")
    legacy = [{"TLSv1": "TLS 1.0", "TLSv1.1": "TLS 1.1"}[v]
              for v in d.get("versions") or [] if v in ("TLSv1", "TLSv1.1")]
    if re.search(r"^SSLv|TLSv1(\.0)?$|TLSv1\.1", protocol):
        sev = "critical"
    else:
        sev = {"TLSv1.2": "info", "TLSv1.3": "pass"}.get(protocol)
    if sev == "critical":
        out.append(_r("critical", f"Outdated TLS protocol negotiated: {protocol}",
                      "Disable TLS 1.0 and 1.1 on the server"))
    elif legacy:
        out.append(_r("issue", f"Server still accepts {' and '.join(legacy)}",
                      "Browsers dropped these in 2020 and they have known weaknesses, so disable them"))
    if sev == "info":
        out.append(_r("info", "TLS 1.2 in use, consider enabling TLS 1.3"))
    elif sev == "pass":
        out.append(_r("pass", "TLS 1.3 negotiated"))
    if d.get("forwardSecrecy") is False:
        out.append(_r("warning", "No forward secrecy in negotiated cipher", "Prefer ECDHE or DHE cipher suites"))
    if d.get("ocspStapled") is False:
        out.append(_r("info", "OCSP stapling not enabled",
                      "Enable OCSP stapling to speed up cert revocation checks"))
    if d.get("alpnProtocol") == "h2":
        out.append(_r("pass", "HTTP/2 negotiated via ALPN"))
    return out


_GRADE_SEV = {"A+": "pass", "A": "pass", "A-": "pass", "B": "warning", "C": "issue",
              "D": "issue", "E": "critical", "F": "critical", "T": "critical", "M": "critical"}


def tls_security_audit(d: dict) -> list[Result]:
    grades = [e["grade"] for e in d.get("endpoints") or []
              if isinstance(e, dict) and isinstance(e.get("grade"), str)]
    if not grades:
        return []
    order = list(_GRADE_SEV)
    worst = max(grades, key=lambda g: order.index(g) if g in order else -1)
    rank = ["pass", "info", "warning", "issue", "critical"]
    sev = max((_GRADE_SEV.get(g, "info") for g in grades), key=rank.index)
    return [_r("pass", f"SSL Labs grade {worst}") if sev == "pass" else
            _r(sev, f"SSL Labs grade {worst}", "Review cipher suites, protocol versions and key strength")]


def tls_client_compat(d: dict) -> list[Result]:
    fails = []
    for e in d.get("endpoints") or []:
        sims = ((e or {}).get("details") or {}).get("sims", {}).get("results") if isinstance(e, dict) else None
        for s in sims or []:
            if isinstance(s, dict) and s.get("errorCode"):
                fails.append(s)
    if not fails:
        return []
    sample = ", ".join(
        f"{(s.get('client') or {}).get('name') or 'client'} {(s.get('client') or {}).get('version') or ''}".strip()
        for s in fails[:5])
    more = f" (+{len(fails) - 5} more)" if len(fails) > 5 else ""
    return [_r("warning", f"{len(fails)} simulated client(s) cannot connect",
               f"{sample}{more}. Drop legacy ciphers/protocols only after weighing reach")]


# ── DNS / domain ───────────────────────────────────────────────

def dnssec(d: dict) -> list[Result]:
    if _dict(d.get("DNSKEY")).get("isFound") and _dict(d.get("DS")).get("isFound"):
        return [_r("pass", "DNSSEC enabled")]
    return [_r("warning", "DNSSEC not enabled", "Sign DNS records to prevent spoofing and cache poisoning")]


def caa_records(d: dict) -> list[Result]:
    records = [r for r in d.get("records") or [] if isinstance(r, dict)]
    issue = [r for r in records if r.get("tag") == "issue"]
    if not issue:
        return [_r("warning", "CAA records have no issue tag" if records else "No CAA records",
                   "Any certificate authority can issue certificates for this domain")]
    issuers = list(dict.fromkeys(
        v for v in (str(r.get("value", "")).split(";")[0].strip() for r in issue) if v))
    if not issuers:
        return [_r("info", "CAA blocks all certificate issuance")]
    return [_r("pass", f"CAA limits issuance to {len(issuers)} CA(s)", ", ".join(issuers))]


def domain_info(d: dict) -> list[Result]:
    days = _days_until(d.get("expires"))
    if days is None:
        return []
    if days < 0:
        return [_r("critical", "Domain registration expired", f"Expired {-days} day(s) ago, renew before it drops")]
    if days <= 7:
        return [_r("critical", "Domain expires within a week", f"Expires in {days} day(s), renew immediately")]
    if days <= 30:
        return [_r("warning", "Domain expires within a month", f"Expires in {days} day(s)")]
    return [_r("pass", "Domain registration is valid")]


def _find_records(txt, prefix: str) -> list[str]:
    out = []
    for chunks in txt or []:
        rec = "".join(chunks) if isinstance(chunks, list) else str(chunks)
        if rec.lower().startswith(prefix.lower()):
            out.append(rec)
    return out


def _tags(record: str) -> dict:
    out = {}
    for part in record.split(";"):
        tag, _, value = part.partition("=")
        out[tag.strip().lower()] = value.strip()
    return out


def _enforced(policy: str = "") -> bool:
    return (policy or "").lower() in ("quarantine", "reject")


def _spf_fails_unlisted(spf: str) -> bool:
    terms = spf.lower().split(" ")
    allw = next((t for t in terms if t in ("all", "+all", "-all", "~all", "?all")), None)
    if allw:
        return allw in ("-all", "~all")
    return any(t.startswith("redirect=") for t in terms)


def _sends_no_mail(d: dict) -> bool:
    spf = (_find_records(d.get("txtRecords"), "v=spf1") or [""])[0]
    return " ".join(spf.lower().split()) == "v=spf1 -all"


def mail_config(d: dict) -> list[Result]:
    out: list[Result] = []
    txt = d.get("txtRecords")

    # SPF
    spf = _find_records(txt, "v=spf1")
    if not spf:
        out.append(_r("issue", "No SPF record found",
                      "Publish a v=spf1 TXT record listing the servers allowed to send mail for this domain, or v=spf1 -all if it sends none"))
    elif len(spf) > 1:
        out.append(_r("issue", "Multiple SPF records found",
                      "Receivers treat this as an SPF error, so merge them into a single v=spf1 record"))
    elif (d.get("spfLookups") or 0) > 10:
        out.append(_r("issue", f"SPF record needs {d['spfLookups']} DNS lookups, over the limit of 10",
                      "Receivers stop at 10 and treat SPF as failed. Remove includes you no longer use, or replace some with ip4/ip6 ranges"))
    elif not _spf_fails_unlisted(spf[0]):
        out.append(_r("warning", "SPF record doesn't fail unlisted senders",
                      "End the record with -all or ~all so mail from servers it does not list fails SPF"))
    else:
        out.append(_r("pass", "SPF record published"))

    # DMARC
    dmarc = _find_records(txt, "v=DMARC1")
    dmarc_domain = d.get("dmarcDomain")
    if not dmarc:
        out.append(_r("issue", "No DMARC record found",
                      "Publish a v=DMARC1 TXT record on the _dmarc subdomain so receivers can act on spoofed mail"))
    elif len(dmarc) > 1:
        out.append(_r("issue", "Multiple DMARC records found",
                      "Receivers ignore DMARC when there is more than one record, so merge them into one"))
    else:
        tags = _tags(dmarc[0])
        tag = "sp" if dmarc_domain and tags.get("sp") else "p"
        policy = (tags.get(tag) or "").lower()
        frm = f" (from {dmarc_domain})" if dmarc_domain else ""
        try:
            pct = int(tags["pct"]) if tags.get("pct") else 100
        except ValueError:
            pct = 100
        if not _enforced(policy):
            nxt = f"set {tag}=quarantine or {tag}=reject"
            out.append(_r("warning", f"DMARC policy is monitor-only{frm}",
                          f"Mail that fails DMARC is still delivered. Once reports show your own mail passing, {nxt}"
                          if tags.get("rua") else
                          f"Mail that fails DMARC is still delivered, and no reports are sent. Add rua=mailto:<address> to get reports, then {nxt}"))
        elif pct < 100:
            out.append(_r("warning", f"DMARC policy only applies to {pct}% of failing mail{frm}",
                          "Raise pct to 100, or remove it, so the policy applies to all failing mail"))
        else:
            out.append(_r("pass", f"DMARC policy: {policy}{frm}"))
        sp = tags.get("sp")
        if not dmarc_domain and sp and _enforced(tags.get("p")) and not _enforced(sp):
            out.append(_r("warning", "DMARC policy doesn't cover subdomains",
                          f"sp={sp} lets spoofed mail from subdomains through. Set sp=quarantine or sp=reject, or remove sp so subdomains follow p"))

    # DKIM
    keys = [k for k in d.get("dkim") or [] if isinstance(k, dict)]
    names = lambda ks: ", ".join(str(k.get("selector")) for k in ks)
    weak = [k for k in keys if k.get("bits") and k["bits"] < 1024]
    short = [k for k in keys if k.get("bits") == 1024]
    if "dkim" in d:  # older web-check versions don't probe DKIM selectors
        if not keys and _sends_no_mail(d):
            out.append(_r("pass", "Domain sends no mail, so DKIM isn't needed"))
        elif not keys:
            out.append(_r("info", "No DKIM key found on common selectors",
                          "DKIM can use any selector name, so it may be set up under one we don't check. If not, publish a DKIM key so receivers can verify your mail"))
        elif weak:
            out.append(_r("issue", f"DKIM key under 1024 bits ({names(weak)})",
                          "Receivers ignore signatures from keys this short. Replace it with a 2048-bit key"))
        elif short:
            out.append(_r("info", f"1024-bit DKIM key ({names(short)})",
                          "2048-bit keys are recommended. Rotate to a 2048-bit key, or ask your mail provider to"))
        else:
            out.append(_r("pass", f"DKIM key found ({names(keys)})"))

    # MTA-STS, TLS-RPT, DANE
    hosts = [str(m.get("exchange", "")).lower() for m in d.get("mxRecords") or [] if isinstance(m, dict)]
    hosts = [h for h in hosts if h]
    policy = d.get("mtaSts")
    if hosts:
        if not policy:
            out.append(_r("info", "MTA-STS not set up",
                          "Without it, mail sent to this domain can be forced back to unencrypted delivery"))
        elif not policy.get("mode"):
            out.append(_r("warning", "MTA-STS policy is unreadable or invalid",
                          "Senders need one v=STSv1 record, and a valid mta-sts.<domain>/.well-known/mta-sts.txt"))
        else:
            pats = [str(p).lower().rstrip(".") for p in policy.get("mx") or []]
            covers = lambda p, h: (h.split(".", 1)[-1] == p[2:]) if p.startswith("*.") else h == p
            missing = [h for h in hosts if not any(covers(p, h) for p in pats)]
            mode = policy["mode"]
            if missing and mode != "none":
                out.append(_r("issue" if mode == "enforce" else "warning",
                              f"MTA-STS policy leaves out {', '.join(missing)}",
                              "Senders refuse to deliver to MX hosts an enforced policy leaves out, so add mx: lines"))
            elif mode != "enforce":
                out.append(_r("info", f"MTA-STS is in {mode} mode",
                              "Switch the policy to mode: enforce once TLS reports show mail arriving encrypted"))
            else:
                out.append(_r("pass", "MTA-STS policy enforced"))
    if policy or d.get("dane"):
        out.append(_r("pass", "TLS-RPT reports set up") if _find_records(txt, "v=TLSRPTv1") else
                   _r("info", "No TLS-RPT record",
                      "Publish a v=TLSRPTv1 TXT record on _smtp._tls, to hear when mail to you fails TLS"))
    if d.get("dane"):
        out.append(_r("pass", f"DANE TLSA records on {len(d['dane'])} of {len(hosts)} MX host(s)"))
    return out


def security_txt(d: dict) -> list[Result]:
    if not d.get("isPresent"):
        return [_r("warning", "No security.txt published",
                   "Add /.well-known/security.txt with disclosure contact info")]
    fields = _dict(d.get("fields"))
    field = lambda name: next((v for k, v in fields.items()
                               if re.sub(r"\d+$", "", k.lower()) == name), None)
    out = [_r("pass", "security.txt found")]
    if not field("contact"):
        out.append(_r("issue", "security.txt has no Contact field",
                      "Contact is required, as it tells researchers how to report a vulnerability"))
    days = _days_until(field("expires"))
    if days is None:
        out.append(_r("warning", "security.txt has no valid Expires date",
                      "Expires is required. Set it under a year ahead, like 2027-01-01T00:00:00Z"))
    elif days < 0:
        out.append(_r("warning", f"security.txt expired {-days} day(s) ago",
                      "Researchers treat an expired file as out of date, so review it and move Expires on"))
    elif days > 366:
        out.append(_r("info", "security.txt expires over a year ahead",
                      "Keep Expires under a year ahead, so the file gets reviewed regularly"))
    if not d.get("isPgpSigned"):
        out.append(_r("info", "security.txt not PGP signed",
                      "Sign the file to let researchers verify authenticity"))
    return out


# ── Reputation / exposure ──────────────────────────────────────

def threats(d: dict) -> list[Result]:
    out = []
    if _dict(d.get("safeBrowsing")).get("unsafe"):
        out.append(_r("critical", "Listed by Google Safe Browsing",
                      "Site flagged for malware, phishing or unwanted software"))
    if (_dict(d.get("urlHaus")).get("urls") or []):
        out.append(_r("critical", "Listed on URLhaus malware feed"))
    phish = _dict(_dict(d.get("phishTank")).get("url0"))
    if phish.get("in_database") in ("true", True) and phish.get("valid") in ("true", True):
        out.append(_r("critical", "Listed on PhishTank"))
    if _dict(d.get("cloudmersive")).get("CleanResult") is False:
        out.append(_r("critical", "Cloudmersive flagged this site as unsafe"))
    return out or [_r("pass", "No threat feed matches")]


def block_lists(d: dict) -> list[Result]:
    if not isinstance(d.get("blocklists"), list):
        return []
    blocked = [b for b in d["blocklists"] if isinstance(b, dict) and b.get("isBlocked")]
    if not blocked:
        return [_r("pass", "Not on any tested DNS blocklist")]
    return [_r("critical" if len(blocked) >= 3 else "issue",
               f"Blocked by {len(blocked)} DNS resolver(s)",
               f"Listed by {', '.join(str(b.get('server')) for b in blocked)}")]


def breaches(d: dict) -> list[Result]:
    items = [b for b in d.get("breaches") or [] if isinstance(b, dict)]
    if not items:
        return [_r("pass", "No known data breaches")]
    leaked = any(b.get("verified") and "Passwords" in (b.get("exposed") or []) for b in items)
    risk = ". Passwords were exposed, so watch for credential stuffing" if leaked else ""
    return [_r("issue" if leaked else "warning", f"Found in {len(items)} data breach(es)",
               f"Latest was {items[0].get('title')} on {items[0].get('date')}{risk}")]


def firewall(d: dict) -> list[Result]:
    if d.get("hasWaf"):
        return [_r("pass", f"WAF detected: {d.get('waf') or 'unknown'}")]
    return [_r("warning", "No web application firewall detected",
               "Consider Cloudflare, AWS WAF or similar to filter malicious traffic")]


def cookies(d: dict) -> list[Result]:
    out = []
    n = 0
    for line in d.get("headerCookies") or []:
        if not isinstance(line, str):
            continue
        parts = re.split(r";\s*", line)
        name = parts[0].split("=")[0].strip()
        if not name:
            continue
        n += 1
        attrs = [p.split("=")[0].strip().lower() for p in parts[1:]]
        if "secure" not in attrs:
            out.append(_r("issue", f'Cookie "{name}" missing Secure flag'))
        if "httponly" not in attrs:
            out.append(_r("warning", f'Cookie "{name}" missing HttpOnly flag'))
        if "samesite" not in attrs:
            out.append(_r("warning", f'Cookie "{name}" missing SameSite flag'))
    if n and not out:
        out.append(_r("pass", "All cookies use Secure/HttpOnly/SameSite"))
    return out


_TRACKER_SEV = {"Advertising": "warning", "Adult Advertising": "warning", "Site Analytics": "info"}


def trackers(d: dict) -> list[Result]:
    items = [t for t in d.get("trackers") or [] if isinstance(t, dict)]
    others = [str(o) for o in d.get("otherTrackers") or []]
    names = lambda ts: ", ".join(str(t.get("name")) for t in ts)
    ads = [t for t in items if _TRACKER_SEV.get(t.get("category")) == "warning"]
    analytics = [t for t in items if _TRACKER_SEV.get(t.get("category")) == "info"]
    out = []
    if ads:
        out.append(_r("warning", f"Loads {len(ads)} advertising tracker(s)", names(ads)))
    if analytics:
        out.append(_r("info", f"Reports to {len(analytics)} analytics service(s)", names(analytics)))
    if others:
        out.append(_r("info", f"Contacts {len(others)} other tracking host(s)", ", ".join(others)))
    return out or [_r("pass", "No trackers found")]


def headers(d: dict) -> list[Result]:
    return [_r("info", f"Server discloses {k}", f"Value: {str(d[k])[:80]}")
            for k in ("x-powered-by", "server", "x-aspnet-version", "x-aspnetmvc-version") if d.get(k)]


_RISKY_PORTS = {
    21: ("warning", "FTP (cleartext file transfer)"),
    23: ("critical", "Telnet (cleartext shell)"),
    25: ("info", "SMTP (mail server)"),
    110: ("warning", "POP3 (cleartext mail)"),
    143: ("warning", "IMAP (cleartext mail)"),
    3306: ("critical", "MySQL exposed to the internet"),
    3389: ("warning", "RDP exposed to the internet"),
    5900: ("warning", "VNC exposed to the internet"),
}


def ports(d: dict) -> list[Result]:
    out = []
    for p in d.get("openPorts") or []:
        if p in _RISKY_PORTS:
            sev, desc = _RISKY_PORTS[p]
            out.append(_r(sev, f"Port {p} open: {desc}", "Close it or restrict access by firewall if not required"))
    return out


# ── Site behaviour / metadata ──────────────────────────────────

def redirects(d: dict) -> list[Result]:
    chain = [u for u in d.get("redirects") or [] if isinstance(u, str)]
    if not chain:
        return []
    out = []
    hops = len(chain) - 1
    if hops >= 4:
        out.append(_r("warning", f"Long redirect chain: {hops} hops", "Collapse intermediate redirects to reduce latency"))
    elif hops > 0:
        out.append(_r("info", f"{hops} redirect hop(s)"))
    if re.match(r"^http://", chain[0], re.I):
        if re.match(r"^https://", chain[-1], re.I):
            out.append(_r("pass", "HTTP requests are redirected to HTTPS"))
        else:
            out.append(_r("critical", "Site does not enforce HTTPS", "Add a permanent redirect from http:// to https://"))
    return out


def status(d: dict) -> list[Result]:
    out = []
    code = d.get("responseCode")
    if isinstance(code, (int, float)):
        out.append(_r("pass", f"Site responded with {int(code)}"))
    ms = d.get("responseTime")
    if isinstance(ms, (int, float)):
        if ms >= 5000:
            out.append(_r("warning", f"Slow response time: {ms:,.0f}ms",
                          "Investigate server performance, caching or CDN coverage"))
        elif ms >= 2000:
            out.append(_r("info", "Response time over 2,000ms"))
    return out


def social_tags(d: dict) -> list[Result]:
    required = (("ogTitle", "OpenGraph Title"), ("ogDescription", "OpenGraph Description"),
                ("ogImage", "OpenGraph Image"), ("twitterCard", "Twitter Card"))
    missing = [label for key, label in required if not d.get(key)]
    if not missing:
        return [_r("pass", "Social share metadata complete")]
    return [_r("warning", f"Missing social tags: {len(missing)}",
               f"Add {', '.join(missing)} for cleaner share previews")]


def social_presence(d: dict) -> list[Result]:
    profiles = [p for p in d.get("profiles") or [] if isinstance(p, dict)]
    label = lambda p: f"{p.get('network')} @{p.get('handle')}"
    missing = [p for p in profiles if p.get("exists") is False]
    unconfirmed = [p for p in profiles if p.get("exists") and not p.get("domainVerified") and not p.get("linksBack")]
    confirmed = [p for p in profiles if p.get("exists") and (p.get("domainVerified") or p.get("linksBack"))]
    unchecked = [p for p in profiles if p.get("checked") is False]
    out = []
    if missing:
        out.append(_r("issue", f"Social account not found: {len(missing)}",
                      f"This site points to {', '.join(map(label, missing))}, which does not exist"))
    if unconfirmed:
        out.append(_r("warning", f"Unconfirmed social accounts: {len(unconfirmed)}",
                      f"{', '.join(map(label, unconfirmed))} does not link back to this site"))
    if not out and confirmed and not unchecked:
        out.append(_r("pass", "Social accounts link back to this site"))
    return out


def robots_txt(d: dict) -> list[Result]:
    rules = [r for r in d.get("robots") or [] if isinstance(r, dict)]
    groups: list[dict] = []
    for rule in rules:
        field, val = str(rule.get("lbl", "")).lower(), str(rule.get("val", ""))
        last = groups[-1] if groups else None
        if field == "user-agent":
            if last and not last["rules"]:
                last["agents"].append(val.lower())
            else:
                groups.append({"agents": [val.lower()], "rules": []})
        elif last and field in ("allow", "disallow"):
            last["rules"].append(f"{field} {val}")
    named = [g for g in groups if "googlebot" in g["agents"]]
    applied = [r for g in (named or [g for g in groups if "*" in g["agents"]]) for r in g["rules"]]
    if ("disallow /" in applied or "disallow /*" in applied) and "allow /" not in applied:
        return [_r("warning", "robots.txt blocks Google from the entire site",
                   "Confirm this is intentional, otherwise the site won't appear in Google search")]
    return []


def shodan_vulns(d: dict) -> list[dict]:
    """CVEs from a Shodan host response, riskiest first (port of getVulns)."""
    found: dict[str, dict] = {}
    for b in d.get("data") or []:
        if not isinstance(b, dict):
            continue
        for vid, v in _dict(b.get("vulns")).items():
            v = _dict(v)
            found[vid] = {"id": vid, "cvss": v.get("cvss"), "epss": v.get("epss"), "kev": v.get("kev"),
                          "port": b.get("port"), "product": b.get("product")}
    raw = d.get("vulns") or []
    for vid in (raw.keys() if isinstance(raw, dict) else raw):
        found.setdefault(vid, {"id": vid})
    num = lambda x: x if isinstance(x, (int, float)) else 0
    return sorted(found.values(), key=lambda v: (not v.get("kev"), -num(v.get("epss")), -num(v.get("cvss"))))


def vulnerabilities(d: dict) -> list[Result]:
    vulns = shodan_vulns(d)
    if not vulns:
        return [_r("pass", "No known CVEs on this host")]
    exploited = sum(1 for v in vulns if v.get("kev"))
    note = f"{exploited} known to be exploited in the wild. " if exploited else ""
    cves = ", ".join(v["id"] for v in vulns[:8])
    more = f" (+{len(vulns) - 8} more)" if len(vulns) > 8 else ""
    sev = "critical" if exploited else "issue" if (vulns[0].get("epss") or 0) >= 0.1 else "warning"
    return [_r(sev, f"Shodan reports {len(vulns)} CVE(s) on this host",
               f"{note}{cves}{more}. Patch affected services or block at the firewall")]


# ── Runner ─────────────────────────────────────────────────────

def _dict(x) -> dict:
    return x if isinstance(x, dict) else {}


# data key -> rule. "domain" falls back to whois (see analyze).
RULES: dict[str, Callable[[dict], list[Result]]] = {
    "http-security": http_security, "mixed-content": mixed_content, "hsts": hsts, "ssl": ssl,
    "dnssec": dnssec, "caa-records": caa_records, "security-txt": security_txt,
    "threats": threats, "breaches": breaches, "block-lists": block_lists,
    "firewall": firewall, "cookies": cookies, "trackers": trackers, "headers": headers,
    "ports": ports, "mail-config": mail_config, "tls-connection": tls_connection,
    "tls-security-audit": tls_security_audit, "tls-client-compat": tls_client_compat,
    "social-tags": social_tags, "social-presence": social_presence,
    "domain-info": domain_info, "status": status, "redirects": redirects,
    "robots-txt": robots_txt, "vulnerabilities": vulnerabilities,
}


def analyze(data: dict) -> list[tuple]:
    """Run every rule over a scan. Returns (severity, check, title, detail)."""
    findings = []
    for key, rule in RULES.items():
        src = {"domain-info": "domain", "tls-client-compat": "tls-security-audit",
               "vulnerabilities": "shodan"}.get(key, key)
        d = data.get(src)
        if key == "domain-info" and not _dict(d).get("expires"):
            d = data.get("whois")
        if not isinstance(d, dict) or d.get("error") or d.get("skipped"):
            continue
        try:
            findings += [(s, key, t, det) for s, t, det in rule(d)]
        except Exception:  # one bad payload shouldn't hide the other advisories
            continue
    findings.sort(key=lambda f: SEVERITIES.index(f[0]))
    return findings
