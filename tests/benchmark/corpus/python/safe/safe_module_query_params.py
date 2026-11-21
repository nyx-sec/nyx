# The query text is a module-level constant; the request value is passed as
# a bound parameter.
from flask import Flask, request
from .db import get_cursor

app = Flask(__name__)

QUERY = """
    SELECT id, name
    FROM users
    WHERE email = %(email)s
"""


@app.route('/u')
def u():
    with get_cursor() as cursor:
        cursor.execute(QUERY, {'email': request.args.get('email')})
        return {'rows': cursor.fetchall()}
