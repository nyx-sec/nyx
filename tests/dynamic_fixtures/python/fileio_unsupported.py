"""File I/O — unsupported fixture (low confidence).

Expected verdict: Unsupported(ConfidenceTooLow)
"""


def read_config(path):
    """Vulnerable function in unsupported-confidence test."""
    with open(path) as f:
        return f.read()
