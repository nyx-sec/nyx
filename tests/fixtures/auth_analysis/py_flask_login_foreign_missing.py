from flask import Flask
from flask_login import login_required

app = Flask(__name__)


@app.route("/docs/<doc_id>")
@login_required
def show_foreign_flask_doc(doc_id):
    doc = Doc.query.filter_by(id=doc_id).first()
    return {"t": doc.title}
