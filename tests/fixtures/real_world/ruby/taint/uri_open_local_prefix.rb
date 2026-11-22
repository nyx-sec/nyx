require "open-uri"

class FetchController < ApplicationController
  # Vulnerable: `URI.open` falls back to `Kernel#open` for a string without a
  # scheme, so a `/srv/uploads/` prefix names a local file and `../` escapes.
  def show
    name = params[:name]
    URI.open("/srv/uploads/#{name}")
    head :ok
  end

  # Safe: the prefix fixes scheme and host.
  def remote
    name = params[:name]
    URI.open("https://assets.example.com/files/#{name}")
    head :ok
  end
end
