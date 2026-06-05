# Python JSON_PARSE depth-bomb vuln fixture.
#
# Models a config-driven JSON ingest endpoint that picks the parser
# input based on the request payload tag - `*_DEEP` routes through a
# deeply-nested array literal (256 levels) that drives `json.loads`
# past the 64-level depth budget; `*_SHALLOW` routes through a flat
# `[]` parse that leaves the predicate clear.  This shape is needed by
# the differential runner: the vuln-payload attempt and the
# benign-control attempt both load the same fixture, and only the
# payload-routed deep branch trips the `JsonParseExcessiveDepth`
# predicate.
import json


def run(value):
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    elif not isinstance(value, str):
        value = str(value)
    if "DEEP" in value:
        nested = "[" * 256 + "]" * 256
        return json.loads(nested)
    return json.loads("[]")
