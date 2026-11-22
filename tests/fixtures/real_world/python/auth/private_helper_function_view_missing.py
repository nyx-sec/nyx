from .models import Document


# A module-private helper called only by a function view.  The view is a web
# entry (it takes `request`), so the helper's id is attacker controlled.
def _fetch(doc_id):
    return Document.objects.get(id=doc_id)


def doc_view(request, doc_id):
    return _fetch(doc_id)
