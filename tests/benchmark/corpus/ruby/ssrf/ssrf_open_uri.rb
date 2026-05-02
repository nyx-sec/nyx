require 'open-uri'

def fetch_url(params)
  url = params[:url]
  OpenURI.open_uri(url)
end
