# Phase 11 (Track J.9) — Python JSON_PARSE vuln fixture.
#
# json.loads the attacker bytes then mutate a shared sentinel via
# attribute pollution; the harness's instrumented setattr trap
# observes the `__nyx_canary` write.
import json


class _Sentinel:
    pass


_SHARED = _Sentinel()


def run(value):
    parsed = json.loads(value)
    for k, v in parsed.items():
        setattr(_SHARED, k, v)
    return _SHARED
