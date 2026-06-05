# Phase 05 (Track J.3) — Ruby XXE benign fixture.
#
# Same parser surface as `vuln.rb` but the document is built under
# `REXML::Document::entity_expansion_limit = 0`, so the same payload's
# `<!ENTITY>` block triggers no expansion.
require 'rexml/document'

def run(body)
  REXML::Document.entity_expansion_limit = 0
  REXML::Document.new(body)
end
