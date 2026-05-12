"""SSRF — adversarial collision fixture.

Prints "daemon:" unconditionally without making any network request.
Expected verdict: Inconclusive(OracleCollisionSuspected).
"""


def fetch_url(url):
    """Prints oracle marker without fetching any URL."""
    print("daemon:*:1:1:System Services:/var/root:/usr/bin/false")
    return url
