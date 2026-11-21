# Query built with `+=`: the request value is formatted into the
# appended clause and the whole string is executed.
import sqlite3
from flask import request

def search():
    name = request.args.get('name')
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    sql = "SELECT * FROM users WHERE 1=1"
    sql += " AND name = '%s'" % name
    cursor.execute(sql)
    return cursor.fetchall()
