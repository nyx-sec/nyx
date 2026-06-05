"""Phase 12 — CLI shape, vulnerable.

Driven via `if __name__ == "__main__":` — Nyx harness sets
`sys.argv[1]` to the payload and either calls `main()` or
`runpy.run_module(..., run_name="__main__")` to fire the guard block.
"""
import subprocess
import sys


def main():
    """Vulnerable: read host from argv[1] and shell out."""
    host = sys.argv[1] if len(sys.argv) > 1 else ""
    result = subprocess.run(
        "ping -c 1 " + host,
        shell=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    print(result.stdout)
    print(result.stderr, end="")


if __name__ == "__main__":
    main()
