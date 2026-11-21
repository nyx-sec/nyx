import yaml
from flask import request
from yaml import SafeLoader


def load_config_file(path):
    with open(path) as f:
        return yaml.load(f, Loader=yaml.SafeLoader)


def load_upload_safe():
    body = request.get_data()
    return yaml.load(body, Loader=yaml.SafeLoader)


def load_upload_bare_name():
    body = request.get_data()
    return yaml.load(body, Loader=SafeLoader)


def load_upload_positional():
    body = request.get_data()
    return yaml.load(body, yaml.CSafeLoader)


def load_upload_default():
    body = request.get_data()
    return yaml.load(body)


def load_upload_full_loader():
    body = request.get_data()
    return yaml.load(body, Loader=yaml.FullLoader)


def load_upload_unsafe_loader():
    body = request.get_data()
    return yaml.load(body, Loader=yaml.UnsafeLoader)
