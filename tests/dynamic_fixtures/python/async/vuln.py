"""Phase 12 — async coroutine, vulnerable.

`async def` coroutine that shells out with concatenated user input.
Nyx harness wraps the call in `asyncio.run`.
"""
import asyncio
import subprocess


async def run_ping(host):
    """Vulnerable async coroutine."""
    await asyncio.sleep(0)
    result = subprocess.run(
        "ping -c 1 " + host,
        shell=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    print(result.stdout)
    print(result.stderr, end="")
