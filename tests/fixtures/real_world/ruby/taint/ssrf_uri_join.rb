require 'net/http'
require 'uri'

class ProxyController < ApplicationController
  # Vulnerable: `URI.join("https://api/", "//evil/x")` is `https://evil/x`.
  def show
    path = params[:path]
    uri = URI.join("https://api.example.com/", path)
    Net::HTTP.get(uri)
  end

  # Safe: a fixed `v1/` head is a relative reference under the base.
  def item
    id = params[:id]
    uri = URI.join("https://api.example.com/", "v1/items/" + id)
    Net::HTTP.get(uri)
  end

  # Safe: interpolation with a fixed `scheme://host/` head.
  def lookup
    id = params[:id]
    url = "https://api.example.com/users/#{id}"
    Net::HTTP.get(URI(url))
  end
end
