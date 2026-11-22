class Cond:
    def eval(self, data):
        return 1


def use(data):
    c = Cond()
    c.eval(data)
    c.eval({"x": 1})
