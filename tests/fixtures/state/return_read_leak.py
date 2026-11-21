# The return hands the caller the file's contents, not the file.
# Expected: state-resource-leak on both.

def read_all(p):
    f = open(p)
    return f.read()


def line_count(p):
    f = open(p)
    return len(f.readlines())
