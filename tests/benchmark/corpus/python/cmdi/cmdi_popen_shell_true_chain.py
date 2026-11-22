from subprocess import Popen


def run_shell():
    cmd = input()
    return Popen(cmd, shell=True).communicate()
