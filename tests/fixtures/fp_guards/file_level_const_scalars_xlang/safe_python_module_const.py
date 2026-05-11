"""Module-level scalar constant flows into a cmdi-shaped sink.

`os.system(DEFAULT_CMD)` looks like a shell-injection sink but the argument
binds to a top-level string literal at file load time, so no attacker can
influence the value. The `py.cmdi.os_system` AST pattern and the structural
`cfg-unguarded-sink` rule both fire without file-level const recognition;
the file-scalars suppression closes both.
"""

import os

DEFAULT_CMD = "ls -la /tmp"
RETRIES = 3
ENABLED = True


def run():
    os.system(DEFAULT_CMD)
    os.popen(DEFAULT_CMD)
