from subprocess import Popen


def run():
    script = input()
    Popen(("env", "bash", "-c", script))
