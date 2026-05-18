# Phase 11 (Track J.9) — Ruby JSON_PARSE benign control fixture.
#
# JSON.parse then merge into a freshly allocated `Hash`, so the
# canary trap on `SHARED` cannot fire.
require 'json'

def run(value)
  JSON.parse(value).dup
end
