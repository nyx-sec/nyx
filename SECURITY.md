# Security Policy

## Reporting a vulnerability

Report privately. Do not open a public GitHub issue for a security bug.

Use [GitHub Security Advisories](https://github.com/elicpeter/nyx/security/advisories/new) to file a private report. Only the maintainers see it.

Include:

- Affected version (`nyx --version`) and OS
- Reproduction steps or a minimal PoC
- Impact (RCE, file read or write, sandbox escape, auth bypass in `nyx serve`, etc.)
- Whether you have a fix in mind

You'll get an acknowledgement within 3 business days, and a status update every 7 days until the issue is closed.

## Scope

In scope: bugs that let untrusted input reach the Nyx process and cause harm.

- Code execution in the scanner: parser exploits, deserialization, command injection in helpers, custom-rule sandbox escape.
- Path traversal or arbitrary file access outside the target repo.
- `nyx serve` issues: auth bypass, host-header bypass, CSRF on mutating routes, XSS in the UI, cross-origin access from a non-loopback origin.
- Memory safety bugs in any unsafe Rust we introduce.
- Tampering with `.nyx/` triage state from outside the user's repo.
- Supply chain issues affecting published `nyx-scanner` crates or release artifacts.

Out of scope:

- False positives or missed detections in scan output. File a regular GitHub issue with the rule ID and a fixture.
- Findings Nyx reports against your own code. That's the scanner working, not a Nyx vulnerability.
- Anything requiring physical or local-account access to the user's machine.
- Self-XSS and missing security headers on `127.0.0.1` endpoints. The UI is loopback-only.
- Performance pathologies on hostile input (a 50 GB file, deeply nested grammars). We harden where we can.
- Issues only reachable by a user editing their own `nyx.conf` to weaken defaults.

## Supported versions

| Version | Status                |
|---------|-----------------------|
| 0.6.x   | Supported             |
| 0.5.x   | Critical fixes only   |
| < 0.5   | End of life           |

The project follows [Semantic Versioning](https://semver.org) once it reaches 1.0.0. Until then, breaking changes can land in any minor release.

## Severity

We use [CVSS 3.1](https://www.first.org/cvss/v3.1/specification-document) to rate reports.

| Severity | Examples                                                                                       |
|----------|-----------------------------------------------------------------------------------------------|
| Critical | Unauthenticated RCE in `nyx serve`, custom-rule sandbox escape during a default scan          |
| High     | Auth bypass against `nyx serve`, arbitrary file write outside the repo                        |
| Medium   | Stored XSS in the UI, CSRF on a mutating route, host-header bypass                            |
| Low      | Information disclosure with no privilege change, log-injection, denial of service via input   |

## Disclosure

Coordinated disclosure.

1. We confirm the report and assign severity.
2. We request a CVE through GitHub or MITRE.
3. A fix is developed on a private branch, with backports to supported lines if needed.
4. A new release ships on crates.io and a public advisory goes out.
5. The reporter is credited in the advisory and the changelog, unless they ask to stay anonymous.

Target window from report to fix is 90 days. If you need to publish on a shorter timeline, tell us in the report and we'll work toward it.

## Safe harbor

Good-faith security research is welcome. We won't pursue legal action against researchers who:

- Report privately and give a reasonable window before publishing.
- Test against their own installations, not third-party deployments running Nyx.
- Avoid data destruction, account takeover, and service disruption.
- Stop and reach out if a test starts to affect data or systems they don't own.

If you're not sure whether a test is in scope, ask first.

## Bounty

There is no paid bug bounty program. Credit, a thank-you in the advisory, and a mention in the changelog are what we offer today.

## Security model recap

Nyx runs locally. The browser UI binds to `127.0.0.1` by default, requires a matching `Host` header, and uses a CSRF token on every mutating request. There is no login, no telemetry, and no remote control plane. If you find a way around any of those defaults, that's a security issue and we want to hear about it.
