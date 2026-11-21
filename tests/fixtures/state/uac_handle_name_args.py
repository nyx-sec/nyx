import sys
import tempfile
import threading


# A closed file object keeps its name; reading it is not a use of the handle.
def report(p):
    f = open(p)
    data = f.read()
    f.close()
    sys.stdout.write("closed %s\n" % f.name)
    return data


def spawn(p, pool):
    f = open(p)
    f.close()
    pool.spawn_thread(f.name)
    t = threading.Thread(target=print, args=(f.name,))
    t.start()


def reopen_by_name(data):
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.write(data)
    tmp.close()
    with open(tmp.name) as g:
        return g.read()


def respond(p, resp):
    f = open(p)
    f.close()
    resp.write(f.name)
