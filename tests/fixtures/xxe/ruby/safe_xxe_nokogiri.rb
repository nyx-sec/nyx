# Safe: Nokogiri ≥ 1.10 is XXE-safe by default; the canonical safe-options
# constant `Nokogiri::XML::ParseOptions::DEFAULT_XML` does not include
# NOENT / DTDLOAD / DTDATTR, so the gate's `dangerous_values` list does
# not match and the call is suppressed.
require "nokogiri"

def handle(params)
  body = params["xml"]
  doc = Nokogiri::XML(body, nil, "UTF-8", Nokogiri::XML::ParseOptions::DEFAULT_XML)
  doc.root.text
end
