# The class stores a file on itself and never closes it anywhere.
# Expected: state-resource-leak.


class Tail:
    def __init__(self, path):
        self.fh = open(path)

    def line(self):
        return self.fh.readline()
