import sys
from subprocess import Popen


def install(deps_file):
    dep = input()
    pip_args = [sys.executable, "-m", "pip", "install", dep]
    if Popen(pip_args).wait() != 0:
        raise Exception("install failed")
    Popen(["pip", "install", dep]).wait()
