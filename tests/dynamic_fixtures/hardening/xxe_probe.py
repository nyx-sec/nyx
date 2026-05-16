"""Phase 18 (Track E.2) — XXE sandbox-profile probe.

Simulates the kill path of an XML external-entity payload: the parser
sees a SYSTEM identifier pointing at an attacker-controlled URL and
issues an outbound HTTP fetch to resolve it.  Under the dedicated
`xxe.sb` profile the outbound connect is denied at the kernel level
and surfaces as `EPERM` (errno=1); under the baseline `(allow
default)` the connect proceeds (and times out or hits the reserved
TEST-NET-1 unreachable, which is a distinct error class).

The probe deliberately targets `http://192.0.2.1/leak.dtd` so DNS is
out of the picture — `192.0.2.1` is part of TEST-NET-1 (RFC 5737)
and never has a route on a real network, so the failure mode is the
sandbox EPERM vs. an OS-level connect-fail rather than a DNS lookup
quirk.

Markers printed on stdout:

    xxe:network-denied  errno=1 …        ← sandbox-exec EPERM (acceptance)
    xxe:network-attempted <reason>       ← sandbox allowed the connect
    xxe:probe-error <class> <message>    ← probe-internal failure

Exit codes:

    0 — outbound attempt was permitted by the sandbox layer
    7 — outbound attempt was denied at the kernel (acceptance)
    9 — probe-internal error before a marker could be emitted
"""

from __future__ import annotations

import errno
import socket
import sys

TEST_NET_HOST = "192.0.2.1"  # RFC 5737 TEST-NET-1 — never routed.
TEST_NET_PORT = 80


def main() -> int:
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        try:
            sock.connect((TEST_NET_HOST, TEST_NET_PORT))
        except OSError as exc:
            code = getattr(exc, "errno", None)
            if code == errno.EPERM:
                print(f"xxe:network-denied errno={code} {exc}")
                return 7
            print(
                f"xxe:network-attempted errno={code} {type(exc).__name__} {exc}"
            )
            return 0
        # The connect actually succeeded — extraordinarily unlikely on
        # an unrouted host, but treat it as `network-attempted` too:
        # the sandbox did not short-circuit the outbound.
        print(f"xxe:network-attempted connect-succeeded {TEST_NET_HOST}")
        return 0
    except Exception as exc:
        print(f"xxe:probe-error {type(exc).__name__} {exc}")
        return 9
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
