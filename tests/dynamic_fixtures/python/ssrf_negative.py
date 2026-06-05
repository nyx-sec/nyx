"""SSRF — negative fixture.

Safe function: validates URL scheme and host against an allowlist.
Expected verdict: NotConfirmed.
"""
import urllib.request
import urllib.parse


ALLOWED_SCHEMES = {"https"}
ALLOWED_HOSTS = {"api.example.com", "data.example.com"}


def fetch_url(url):
    """Safe: validates URL before fetching."""
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        print("Invalid URL")
        return

    if parsed.scheme not in ALLOWED_SCHEMES:
        print(f"Scheme not allowed: {parsed.scheme}")
        return
    if parsed.hostname not in ALLOWED_HOSTS:
        print(f"Host not allowed: {parsed.hostname}")
        return

    try:
        with urllib.request.urlopen(url, timeout=3) as resp:
            print(resp.read().decode("utf-8", errors="replace"))
    except Exception as e:
        print(f"Fetch error: {e}", end="")
