"""XSS — unsupported fixture (low confidence).

Expected verdict: Unsupported(ConfidenceTooLow)
"""


def render(input_text):
    """Vulnerable render in unsupported-confidence test."""
    print(f"<span>{input_text}</span>")
