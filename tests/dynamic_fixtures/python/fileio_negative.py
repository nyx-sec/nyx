"""File I/O — negative fixture.

Safe function: validates path stays within allowed directory.
Expected verdict: NotConfirmed.
"""
import os


def read_file(path):
    """Safe: resolves and validates path is within /tmp/safe-uploads/."""
    base_dir = "/tmp/safe-uploads"
    os.makedirs(base_dir, exist_ok=True)
    # Resolve to absolute path and check it stays within base_dir.
    abs_path = os.path.realpath(os.path.join(base_dir, path))
    if not abs_path.startswith(base_dir + os.sep) and abs_path != base_dir:
        print("Access denied: path traversal detected")
        return
    try:
        with open(abs_path) as f:
            print(f.read())
    except FileNotFoundError:
        print("File not found")
