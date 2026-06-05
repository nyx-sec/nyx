"""XSS — negative fixture.

Safe function: uses html.escape() before rendering.
Expected verdict: NotConfirmed (script tag escaped to &lt;script&gt;).
"""
import html


def render_comment(user_input):
    """Safe: HTML-escapes user input before rendering."""
    safe = html.escape(user_input)
    print(f"<div class='comment'>{safe}</div>")
