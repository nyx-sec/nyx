# Negative: Sinatra route with no path captures. The handler takes
# zero block formals; the entry-point seeding pass has nothing to
# paint. The body pipes a static string to `system`, which the
# literal-arg gate suppresses. Forcing-function for the negative
# direction: a future regression that paints non-capture block formals
# would fire here as soon as the fixture grows a formal.
require 'sinatra'

get '/static' do
  system("ls -la")
  "ok"
end
