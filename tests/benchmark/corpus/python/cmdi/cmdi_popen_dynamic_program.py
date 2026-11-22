from subprocess import Popen


def run():
    tool = input()
    Popen([tool, "--version"])
