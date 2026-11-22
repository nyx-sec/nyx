from fastapi import FastAPI
from sqlalchemy import Column, Integer, MetaData, String, Table, select
from sqlalchemy.orm import Session

app = FastAPI()
meta = MetaData()
users = Table("users", meta, Column("id", Integer), Column("name", String))


@app.get("/users/by-id")
def by_id(uid: int, session: Session):
    stmt = select(users).where(users.c.id == uid).order_by(users.c.name)
    return session.execute(stmt).all()


@app.get("/users/sorted")
def sorted_users(sort: str, session: Session):
    stmt = select(users).order_by(sort)
    return session.execute(stmt).all()
