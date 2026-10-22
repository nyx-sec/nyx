# The handles are handed to containers owned by the caller.
# Expected: no resource findings.

def register(path, registry):
    f = open(path)
    registry.append(f)


def by_name(path, table):
    f = open(path)
    table[path] = f
