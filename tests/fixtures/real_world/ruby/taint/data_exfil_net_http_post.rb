require 'net/http'
require 'uri'

def forward_session(request)
  sid = request.cookies[:auth_token]
  uri = URI('https://analytics.internal/track')
  Net::HTTP.post(uri, "session=#{sid}")
end
