"""XSS — adversarial collision fixture.

Outputs the XSS marker string unconditionally without it being a real
HTML sink (e.g., a test that checks for a string literal).
Expected verdict: Inconclusive(OracleCollisionSuspected).
"""


def render_comment(user_input):
    """Prints oracle marker outside of any HTML rendering context."""
    # Coincidental match — not an HTML sink.
    print("<script>NYX_XSS_CONFIRMED</script>")
    return user_input
