from subprocess import Popen


def run():
    ref = input()
    Popen(["git", "log", ref], **{"cwd": "/srv/repo"})
    Popen(args=["git", "log", ref])
    Popen(["bash", "run.sh", ref])
    Popen(["git", "log", ref], 0, None, None, None, None, None, None, False)
