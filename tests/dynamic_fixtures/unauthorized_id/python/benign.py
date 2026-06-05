# Phase 11 (Track J.9) — Python UNAUTHORIZED_ID benign control fixture.
#
# Compares `owner_id` against the authenticated caller and returns
# `None` for any boundary-crossing request.
_STORE = {"alice": {"email": "alice@x"}, "bob": {"email": "bob@x"}}
_CALLER_ID = "alice"


def run(owner_id):
    if owner_id != _CALLER_ID:
        return None
    return _STORE.get(owner_id)
