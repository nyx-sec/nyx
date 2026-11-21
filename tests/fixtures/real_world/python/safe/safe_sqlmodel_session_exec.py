from fastapi import FastAPI
from flask import request
from sqlmodel import Session, select

from models import User, engine

app = FastAPI()


def lookup_user():
    name = request.args.get("name")
    with Session(engine) as session:
        return session.exec(select(User).where(User.name == name)).all()


def run_snippet():
    code = request.args.get("code")
    exec(code)
