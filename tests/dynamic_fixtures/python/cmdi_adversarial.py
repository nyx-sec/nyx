"""Command injection — adversarial collision fixture.

Prints NYX_PWN_791_CMDI unconditionally without going through a shell sink.
Expected verdict: Inconclusive(OracleCollisionSuspected).
"""


def process_input(user_input):
    """Prints oracle marker without using a command execution sink."""
    # Coincidental oracle match — not a shell sink.
    print("NYX_PWN_791_CMDI")
    return user_input.upper()
