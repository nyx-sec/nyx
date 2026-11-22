from subprocess import Popen


def run():
    cmd = input()
    Popen(cmd, 0, None, None, None, None, None, None, True)
