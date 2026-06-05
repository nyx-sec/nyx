# Phase 11 (Track J.9) — Python UNAUTHORIZED_ID vuln fixture.
#
# Looks up a record by `owner_id` without checking it against the
# authenticated caller; an attacker who supplies another user's id
# reads that user's record.
_STORE = {"alice": {"email": "alice@x"}, "bob": {"email": "bob@x"}}
_CALLER_ID = "alice"


def run(owner_id):
    return _STORE.get(owner_id)
