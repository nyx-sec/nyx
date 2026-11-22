from subprocess import Popen


def run():
    cmd = input()
    Popen(cmd, **{"shell": True})
