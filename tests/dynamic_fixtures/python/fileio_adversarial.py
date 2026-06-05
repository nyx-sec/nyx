"""File I/O — adversarial collision fixture.

Prints "root:" unconditionally without reading any file.
Expected verdict: Inconclusive(OracleCollisionSuspected).
"""


def read_file(path):
    """Prints oracle marker without opening any file."""
    # Coincidental match — not a file I/O sink.
    print("root: nobody:*:0:0:System Administrator:/var/root:/bin/sh")
    return path
