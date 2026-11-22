from fastapi import FastAPI
from sqlalchemy import select, text
from sqlalchemy.orm import Session

app = FastAPI()


@app.get("/users/laundered")
def laundered(name: str, uid: int, session: Session):
    stmt = select(User).where(text(f"name = '{name}'"))
    stmt = stmt.where(User.id == uid)
    return session.execute(stmt).all()


@app.get("/users/sorted")
def sorted_users(sort: str, session: Session):
    stmt = select(User).order_by(sort)
    return session.execute(stmt).all()


@app.get("/users/cond")
def cond(name: str, session: Session):
    where_sql = "name = '%s'" % name
    return session.execute(select(User).where(where_sql)).all()


@app.get("/users/param-stmt")
def param_stmt(stmt, uid: int, session: Session):
    stmt = stmt.where(User.id == uid)
    return session.execute(stmt).all()


@app.get("/users/clean-chain")
def clean_chain(name: str, uid: int, page: int, session: Session):
    stmt = select(User).where(User.name == name)
    stmt = stmt.where(User.id == uid)
    stmt = stmt.order_by(User.id).limit(page)
    return session.execute(stmt).all()
