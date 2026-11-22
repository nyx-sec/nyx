class Condition:
    def __init__(self, attr, value):
        self.attr = attr
        self.value = value

    def eval(self, data):
        return data.get(self.attr) == self.value


class ConditionSet:
    def __init__(self, conditions):
        self.conditions = [Condition(**c) for c in conditions]

    def eval(self, data):
        first = Condition("x", 1)
        return first.eval(data)


def check(rules):
    cs = ConditionSet(rules)
    ok = cs.eval({"x": 1})
    single = Condition("x", 1)
    also = single.eval({"x": 1})
    print(ok, also)
