from subprocess import Popen


def install():
    deps = input()
    if Popen(["bash", "-c", f"python -m pip install {deps}"]).wait() != 0:
        raise Exception("install failed")
