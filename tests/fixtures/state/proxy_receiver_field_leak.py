class Session:
    def start(self, p):
        self.fh = open(p)

    def stop(self):
        self.fh.close()


# start() opens a file into the receiver; nothing calls stop().
def leaks(p):
    s = Session()
    s.start(p)
    return 1
