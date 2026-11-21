# The tainted flag only picks the branch; the statement executed in the body
# is a constant.  The `if` header must not take the body's sink.
from flask import request


class Report:
    def run(self):
        flag = request.args.get("flag")
        if flag:
            self.cursor.execute("SELECT 1")
        return "ok"
