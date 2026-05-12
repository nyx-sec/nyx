"""SSRF — positive fixture.

Vulnerable function: fetches a user-controlled URL.
Expected verdict: Confirmed (file:// payload reads /etc/passwd → "root:").
"""
import urllib.request


def fetch_url(url):
    """Vulnerable: fetches URL provided by user without validation."""
    try:
        with urllib.request.urlopen(url, timeout=3) as resp:
            content = resp.read().decode("utf-8", errors="replace")
            print(content)
    except Exception as e:
        print(f"Fetch error: {e}", end="")
