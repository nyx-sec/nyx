"""Phase 12 — CLI shape, benign."""
import re
import subprocess
import sys

_VALID_HOST = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else ""
    if not _VALID_HOST.fullmatch(host):
        print("invalid host")
        return
    result = subprocess.run(
        ["ping", "-c", "1", host],
        shell=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    print(result.stdout)
    print(result.stderr, end="")


if __name__ == "__main__":
    main()
