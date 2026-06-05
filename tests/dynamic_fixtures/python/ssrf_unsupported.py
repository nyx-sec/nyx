"""SSRF — unsupported fixture (low confidence).

Expected verdict: Unsupported(ConfidenceTooLow)
"""
import urllib.request


def fetch(url):
    """Vulnerable function in unsupported-confidence test."""
    return urllib.request.urlopen(url).read()
