# Phase 09 (Track J.7) — Ruby OPEN_REDIRECT benign control fixture.
#
# The function ignores the attacker-supplied value and redirects to a
# same-origin path; the captured `Location:` header carries no
# off-origin authority.
require 'rack'

def run(value)
  response = Rack::Response.new
  response.redirect('/dashboard')
  response
end
