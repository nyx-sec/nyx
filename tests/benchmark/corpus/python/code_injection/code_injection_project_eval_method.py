import sys


class Evaluator:
    def eval(self, expr):
        return eval(expr)


def run_cli(ev):
    ev.eval(sys.argv[1])


def run_df(df):
    q = input()
    return df.eval(q)


def run_builtin():
    expr = sys.argv[1]
    return eval(expr)
