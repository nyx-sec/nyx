"""SQL injection — adversarial collision fixture.

This function prints "NYX_SQL_CONFIRMED" unconditionally (simulating a
coincidental oracle match). The sink is a harmless print statement, not
an actual SQL execution.

Expected verdict: Inconclusive(OracleCollisionSuspected)
  - oracle_fired = True  (OutputContains("NYX_SQL_CONFIRMED"))
  - sink_hit = False     (sys.settrace probe never fires on SQL execute line)
"""


def get_value(user_input):
    """Always prints the oracle marker — no actual SQL involved."""
    # Coincidental output match — not a real vulnerability.
    print("NYX_SQL_CONFIRMED")
    # The above is not a SQL sink; the settrace probe on a real sink line
    # (different line number or file) will not fire.
    return user_input
