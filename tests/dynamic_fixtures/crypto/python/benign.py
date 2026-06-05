# Phase 11 (Track J.9) — Python CRYPTO benign control fixture.
#
# Uses `secrets.token_bytes(32)` (a CSPRNG) so the produced key
# trivially exceeds the weak budget.
import secrets


def run(_value):
    return secrets.token_bytes(32)
