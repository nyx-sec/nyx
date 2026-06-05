"""File I/O — positive fixture.

Vulnerable function: opens a file at a user-controlled path.
Expected verdict: Confirmed (path traversal payload reaches /etc/passwd).
"""


def read_file(path):
    """Vulnerable: reads file at user-controlled path."""
    try:
        with open(path) as f:
            print(f.read())
    except (OSError, PermissionError) as e:
        print(f"Error reading {path}: {e}", end="")
