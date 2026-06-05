"""Phase 12 — async coroutine, benign."""
import asyncio
import re
import subprocess

_VALID_HOST = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


async def run_ping(host):
    await asyncio.sleep(0)
    if not _VALID_HOST.fullmatch(host or ""):
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
