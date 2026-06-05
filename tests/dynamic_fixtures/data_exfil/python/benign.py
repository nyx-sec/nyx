# Phase 11 (Track J.9) — Python DATA_EXFIL benign control fixture.
#
# Sends to a loopback receiver, so the captured host is on-allowlist
# and the predicate stays clear.
import urllib.request

ALLOWLIST = {"127.0.0.1", "localhost"}


def run(host):
    if host not in ALLOWLIST:
        return
    secret = "alice-creds"
    url = f"http://{host}/exfil?token={secret}"
    urllib.request.urlopen(url, timeout=1)
