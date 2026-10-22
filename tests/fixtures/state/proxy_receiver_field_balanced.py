class Worker:
    def start(self, p):
        self.fh = open(p)

    def stop(self):
        self.fh.close()


def balanced(p):
    s = Worker()
    s.start(p)
    s.stop()
    return 1
