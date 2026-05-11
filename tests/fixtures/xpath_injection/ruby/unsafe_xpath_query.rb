# Unsafe: Sinatra params concatenated into an XPath expression and passed to
# Nokogiri's `xpath` method.  Suffix matching on `xpath` catches the
# bound-receiver call directly.
require 'nokogiri'

def lookup(params)
  doc = Nokogiri::XML(File.read("users.xml"))
  user = params[:user]
  expr = "//user[name='#{user}']"
  doc.xpath(expr)
end
