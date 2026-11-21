from flask import Flask
from flask_login import current_user, login_required

app = Flask(__name__)


@app.route("/docs/<doc_id>")
@login_required
def show_flask_owned_doc(doc_id):
    doc = Doc.query.filter_by(id=doc_id, owner=current_user).first()
    return {"t": doc.title}


@app.route("/docs2/<doc_id>")
@login_required
def show_flask_doc_by_owner_id(doc_id):
    doc = Doc.query.filter_by(id=doc_id, owner_id=current_user.id).first()
    return {"t": doc.title}


@app.route("/docs3/<doc_id>")
@login_required
def show_flask_doc_by_association(doc_id):
    doc = current_user.docs.filter_by(id=doc_id).first()
    return {"t": doc.title}
