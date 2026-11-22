NAMES = ["a", "b"]


def drop_all(cur):
    for name in NAMES:
        cur.execute("drop table " + name)
