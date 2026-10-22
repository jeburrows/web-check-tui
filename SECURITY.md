# Security Policy

## Reporting a vulnerability

Please report security issues privately through GitHub:
[Report a vulnerability](https://github.com/jeburrows/web-check-tui/security/advisories/new).

Don't open a public issue for anything exploitable. Include the steps to reproduce,
the affected version or commit, and the impact. You can expect a reply within a
week or so; this is a small spare-time project.

## Scope

This tool is a viewer for [web-check](https://github.com/Lissy93/web-check) results.
In scope: crashes or unsafe handling of untrusted scan data, and anything in
`--scan` that mishandles the API response. Issues in web-check itself belong in
[its repo](https://github.com/Lissy93/web-check/security).

## Supported versions

Only the latest commit on `main`.
