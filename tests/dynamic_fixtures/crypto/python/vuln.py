# Phase 11 (Track J.9) — Python CRYPTO vuln fixture.
#
# Uses `random.randint(0, 0xFFFF)` (a non-CSPRNG) to derive a 16-bit
# key; the harness's instrumented key path writes a `ProbeKind::WeakKey`
# probe and the `WeakKeyEntropy` oracle fires.
import random


def run(_value):
    return random.randint(0, 0xFFFF)
