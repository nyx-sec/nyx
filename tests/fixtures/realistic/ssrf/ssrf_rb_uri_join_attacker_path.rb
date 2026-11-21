# `URI.join(base, path)` resolves `path` as a reference against `base`, so an
# attacker-controlled path can be absolute or protocol-relative and replace the
# literal base's host.
require 'net/http'
require 'uri'

class ProxyController
  def show
    path = params[:path]
    uri = URI.join("https://api.example.com/", path)
    Net::HTTP.get(uri)
  end
end
