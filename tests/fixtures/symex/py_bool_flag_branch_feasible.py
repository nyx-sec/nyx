import os
import subprocess


# `dry_run` is the constant False, so the else branch runs; `quiet` is the
# constant True, so `not quiet` never holds.
def run():
    cmd = os.environ.get("USER_COMMAND")
    dry_run = False
    if dry_run:
        return
    else:
        subprocess.call(cmd, shell=True)
    quiet = True
    if not quiet:
        subprocess.call("echo " + cmd, shell=True)


run()
