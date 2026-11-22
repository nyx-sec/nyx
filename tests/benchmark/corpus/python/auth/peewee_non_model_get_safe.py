from flask import Flask, request

app = Flask(__name__)


class Settings:
    values = {}

    @classmethod
    def get(cls, key):
        return cls.values.get(key)


@app.route("/settings/<key>")
def show_setting(key):
    flag = request.args.get("flag")
    return str(Settings.get(key)) + str(flag)
