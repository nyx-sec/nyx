from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.orm import Session

app = FastAPI()


@app.get("/users")
def users_by_name(name: str, session: Session):
    stmt = select(User).where(User.name == name)
    return session.execute(stmt.order_by(User.id)).all()
