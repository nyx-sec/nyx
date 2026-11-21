# The handle lives on the object and close() releases it.
# Expected: no resource findings.


class LogStore:
    def __init__(self, path):
        self.fh = open(path, "a")

    def write(self, line):
        self.fh.write(line)

    def close(self):
        self.fh.close()
