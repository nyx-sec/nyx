# Ruby JSON_PARSE depth-bomb vuln fixture.
#
# Models a config-driven JSON ingest endpoint that picks the parser
# input based on the request payload tag — `*_DEEP` routes through a
# deeply-nested array literal (256 levels) that drives `JSON.parse`
# past the 64-level depth budget; `*_SHALLOW` routes through a flat
# `[]` parse that leaves the predicate clear.  This shape is needed
# by the differential runner: the vuln-payload attempt and the
# benign-control attempt both load the same fixture, and only the
# payload-routed deep branch trips the `JsonParseExcessiveDepth`
# predicate.  `max_nesting: false` disables the json gem's depth
# guard so the harness's depth walker sees the full 256-level shape
# rather than triggering `JSON::NestingError` at depth 100.
require 'json'

def run(value)
  text = value.to_s
  if text.include?('DEEP')
    nested = '[' * 256 + ']' * 256
    return JSON.parse(nested, max_nesting: false)
  end
  JSON.parse('[]')
end
