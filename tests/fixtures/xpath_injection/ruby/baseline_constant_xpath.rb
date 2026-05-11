# Baseline: expression is a compile-time constant.  No taint reaches
# `doc.xpath` so no XPATH_INJECTION finding fires.
require 'nokogiri'

def lookup
  doc = Nokogiri::XML(File.read("users.xml"))
  doc.xpath("//user[@role='admin']")
end
