from fastapi import FastAPI
from sqlalchemy import select, text
from sqlalchemy.orm import Session

app = FastAPI()


@app.get("/users")
def users_by_name(name: str, session: Session):
    return session.execute(select(User).where(text(f"name = '{name}'"))).all()
