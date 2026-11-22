_NAMES = ["a", "b"]
TABLES = ("c", "d")


def drop_all(cur):
    for name in _NAMES:
        cur.execute("drop table " + name)
    for name in TABLES:
        cur.execute("drop table " + name)
