# Safe: user-supplied substring routed through the project-local
# `escape_xpath` helper before interpolation.  The sanitizer clears
# XPATH_INJECTION so the sink does not fire.
require 'nokogiri'

def escape_xpath(raw)
  raw.gsub("'", '&apos;').gsub('"', '&quot;')
end

def lookup(params)
  doc = Nokogiri::XML(File.read("users.xml"))
  user = params[:user]
  safe = escape_xpath(user)
  expr = "//user[name='#{safe}']"
  doc.xpath(expr)
end
