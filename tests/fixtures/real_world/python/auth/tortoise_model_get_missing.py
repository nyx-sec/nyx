from fastapi import FastAPI
from tortoise.models import Model
from tortoise import fields

app = FastAPI()


class Note(Model):
    title = fields.CharField(max_length=100)


@app.get("/notes/{note_id}")
async def show_note(note_id: str):
    note = await Note.get(id=note_id)
    return {"title": note.title}
