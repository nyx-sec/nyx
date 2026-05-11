"""Pin the Crypto carve-out for the Layer A literal-args suppression.

Pre-fix, ``hashlib.md5(b"hello")`` was treated as "all-literal args"
and silently suppressed. The literal IS the weakness signal here: MD5
is the algorithm choice. Suppressing the call erases the actual
finding even though no taint flows through it.

The same shape applies to ``hashlib.sha1``. Both must keep firing.

CommandExec / SqlInjection patterns stay covered by the literal-args
suppression: a literal command string or literal SQL string carries
no attacker-controlled data, so silencing those is correct. The
``os.system("ls -la")`` call demonstrates the contrast.
"""

import hashlib
import os


def hash_with_literal_bytes() -> bytes:
    return hashlib.md5(b"static-string").hexdigest().encode()


def hash_with_literal_sha1() -> bytes:
    return hashlib.sha1(b"another-static").hexdigest().encode()


def hash_with_user_data(data: bytes) -> bytes:
    return hashlib.md5(data).hexdigest().encode()


def safe_command_literal() -> int:
    return os.system("ls -la /tmp")
