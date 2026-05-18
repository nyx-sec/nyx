# Phase 05 (Track J.3) — Ruby XXE vuln fixture.
#
# The function feeds attacker XML straight to `REXML::Document.new`
# without disabling entity expansion, so any `<!ENTITY xxe SYSTEM
# "file:///…">` in the payload is resolved and its body substituted
# into the parsed document.
require 'rexml/document'

def run(body)
  REXML::Document.new(body)
end
