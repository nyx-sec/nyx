"""XSS — positive fixture.

Vulnerable function: echoes user input directly into HTML without escaping.
Expected verdict: Confirmed (XSS payload echoed verbatim to output).
"""


def render_comment(user_input):
    """Vulnerable: no HTML escaping."""
    html = f"<div class='comment'>{user_input}</div>"
    print(html)
