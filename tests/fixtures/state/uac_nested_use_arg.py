import sys


# The closed handle is read by a call nested inside the outer use.
def nested(p):
    f = open(p)
    f.close()
    sys.stdout.write(f.read())
