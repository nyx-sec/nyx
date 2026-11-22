import sys
from subprocess import Popen


def clustered_flag(script):
    Popen(["bash", "-lc", script])


def env_wrapper(script):
    Popen(("env", "bash", "-c", script))


def interpreter(code):
    Popen(["python", "-c", code])


def args_keyword(name):
    Popen(args=["bash", "-c", f"echo {name}"])


def dynamic_program(tool):
    Popen([tool, "--version"])


def kwargs_shell(cmd):
    Popen(cmd, **{"shell": True})


def positional_shell(cmd):
    Popen(cmd, 0, None, None, None, None, None, None, True)


def truthy_shell(cmd):
    Popen(cmd, shell=1)


clustered_flag(sys.argv[1])
env_wrapper(sys.argv[1])
interpreter(sys.argv[1])
args_keyword(sys.argv[1])
dynamic_program(sys.argv[1])
kwargs_shell(sys.argv[1])
positional_shell(sys.argv[1])
truthy_shell(sys.argv[1])
