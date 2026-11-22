from flask import Flask
from peewee import Model, CharField

app = Flask(__name__)


class Note(Model):
    title = CharField()


@app.route("/notes/<int:note_id>")
def show_note(note_id):
    note = Note.get(Note.id == note_id)
    return note.title
