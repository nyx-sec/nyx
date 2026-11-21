from fastapi import FastAPI

from .db import Doc, session

app = FastAPI()


# Recall guard for `main_ok.py`: no dependency, so the delete is unchecked.
@app.delete("/notes/{note_id}")
def delete_note(note_id: str):
    session.query(Doc).filter(Doc.id == note_id).delete()
    return {"ok": True}
