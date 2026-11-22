from subprocess import Popen


def run():
    script = input()
    Popen(["bash", "-lc", script])
