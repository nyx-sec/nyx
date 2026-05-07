# Unsafe: tainted XML reaches Nokogiri::XML with the NOENT option flag,
# enabling external-entity expansion (XXE).  Nokogiri ≥ 1.10 is XXE-safe
# by default, so the gate fires only when an unsafe option flag is passed
# explicitly at the activation arg position.
require "nokogiri"

def handle(params)
  body = params["xml"]
  doc = Nokogiri::XML(body, nil, "UTF-8", Nokogiri::XML::ParseOptions::NOENT)
  doc.root.text
end
