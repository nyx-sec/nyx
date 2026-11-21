import subprocess


def stop(client):
    res = client.disconnect()
    return str(res)


def again(client):
    status = client.reconnect()
    return str(status)


def run():
    proc = subprocess.Popen(["true"])
    proc.communicate()
