import yaml
from flask import request


def parse_upload():
    body = request.get_data()
    return yaml.load(body, Loader=yaml.SafeLoader)
