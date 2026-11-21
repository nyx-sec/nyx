from fastapi import FastAPI
from sqlalchemy import select, text, update
from sqlalchemy.orm import Session

app = FastAPI()


@app.get("/users/by-name")
def by_name(name: str, session: Session):
    return session.execute(select(User).where(User.name == name)).all()


@app.get("/users/search")
def search(q: str, min_age: int, session: Session):
    stmt = select(User).where(User.name.ilike(f"%{q}%"))
    stmt = stmt.where(User.age >= min_age)
    return session.execute(stmt.order_by(User.id).limit(20)).all()


@app.post("/users/rename")
def rename(old: str, new: str, session: Session):
    session.execute(update(User).where(User.name == old).values(name=new))
    session.commit()


@app.get("/users/raw-fstring")
def raw_fstring(name: str, session: Session):
    return session.execute(text(f"SELECT * FROM users WHERE name = '{name}'")).all()


@app.get("/users/raw-where")
def raw_where(name: str, session: Session):
    return session.execute(select(User).where(text(f"name = '{name}'"))).all()


@app.get("/users/bound-text")
def bound_text(name: str, session: Session):
    return session.execute(text("SELECT * FROM users WHERE name = :n"), {"n": name}).all()
