class Cond:
    def eval(self, data):
        return 1


def use(c, data):
    c.eval(data)
    df.eval(data)
