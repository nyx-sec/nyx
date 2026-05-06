# Unsafe: tainted XML reaches REXML::Document.new, the legacy default-vulnerable
# pure-Ruby XML parser that resolves external entities by default.
require "rexml/document"

def handle(params)
  body = params["xml"]
  doc = REXML::Document.new(body)
  doc.root.text
end
