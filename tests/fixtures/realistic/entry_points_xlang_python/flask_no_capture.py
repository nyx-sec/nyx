# Negative: Flask route with no path captures.  The handler takes zero
# formals; the entry-point seeding pass has nothing to paint.  The body
# pipes a static string to `os.system`, which the literal-arg gate
# suppresses.  Forcing-function for the negative direction: a future
# regression that seeds non-capture formals would fire here as soon as
# the fixture grows a formal.
from flask import Flask
import os

app = Flask(__name__)


@app.route("/static")
def static_route():
    os.system("ls -la")
    return "ok"
