import os
from subprocess import Popen


def install(deps_file):
    deps = input()
    if Popen(["bash", "-c", f"python -m pip install {deps}"]).wait() != 0:
        raise Exception("install failed")


def run_shell(cmd):
    cmd = input()
    return Popen(cmd, shell=True).communicate()
