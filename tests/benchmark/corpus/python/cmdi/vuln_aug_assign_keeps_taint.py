# Appending a literal flag with `+=` keeps the request value in `cmd`.
import os
from flask import request

def run():
    cmd = request.args.get('cmd')
    cmd += ' --verbose'
    os.system(cmd)
