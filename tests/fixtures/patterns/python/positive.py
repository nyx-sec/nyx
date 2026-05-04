# Positive fixture: each snippet should trigger the named pattern.

import os
import subprocess
import pickle
import yaml
import hashlib

# py.code_exec.eval
def trigger_eval(data):
    result = eval(data)

# py.code_exec.exec
def trigger_exec(code):
    exec(code)

# py.code_exec.compile
def trigger_compile(code):
    co = compile(code, "<string>", "exec")

# py.cmdi.os_system
def trigger_os_system(cmd):
    os.system(cmd)

# py.cmdi.os_popen
def trigger_os_popen(cmd):
    os.popen(cmd)

# py.cmdi.subprocess_shell
def trigger_subprocess_shell(cmd):
    subprocess.run(cmd, shell=True)

# py.deser.pickle_loads
def trigger_pickle(data):
    obj = pickle.loads(data)

# py.deser.yaml_load
def trigger_yaml(data):
    obj = yaml.load(data)

# py.sqli.execute_format
def trigger_sql_concat(cursor, user):
    cursor.execute("SELECT * FROM users WHERE name = '" + user + "'")

# py.sqli.execute_format (f-string variant)
def trigger_sql_fstring(cursor, user):
    cursor.execute(f"SELECT * FROM users WHERE name = '{user}'")

# py.sqli.text_format
def trigger_sqlalchemy_text_fstring(connection, user):
    connection.execute(text(f"SELECT * FROM users WHERE name = '{user}'"))

# py.xss.make_response_format
def trigger_make_response_fstring(request, make_response):
    content_type = request.headers.get("Content-Type")
    return make_response(f"Invalid content type: '{content_type}'", 400)

# py.xss.make_response_format (concat variant)
def trigger_make_response_concat(request, make_response):
    name = request.args.get("name")
    return make_response("<h1>Hello " + name + "</h1>")

# py.crypto.md5
def trigger_md5(data):
    hashlib.md5(data)

# py.crypto.sha1
def trigger_sha1(data):
    hashlib.sha1(data)
