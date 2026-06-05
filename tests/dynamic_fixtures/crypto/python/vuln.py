# Phase 11 (Track J.9) — Python CRYPTO vuln fixture.
#
# Models a config-driven crypto endpoint that picks the RNG based on
# the request payload — `*_WEAK` routes through `random.randint(0, 0xFFFF)`
# (a non-CSPRNG) and `*_STRONG` routes through `secrets.token_bytes(32)`
# (a CSPRNG).  This shape is needed by the differential runner: the
# vuln-payload attempt and the benign-control attempt both load the same
# fixture, and only the payload-routed weak branch trips the
# `WeakKeyEntropy` predicate.  Real-world analogue: a JWT-signing or
# session-token endpoint that exposes an `algorithm`/`key_strength`
# knob whose weak setting falls back to a non-CSPRNG seed.
import random
import secrets


def run(value):
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    elif not isinstance(value, str):
        value = str(value)
    if "STRONG" in value:
        return secrets.token_bytes(32)
    return random.randint(0, 0xFFFF)
