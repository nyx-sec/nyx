from subprocess import Popen


def run():
    name = input()
    Popen(args=["bash", "-c", f"echo {name}"])
