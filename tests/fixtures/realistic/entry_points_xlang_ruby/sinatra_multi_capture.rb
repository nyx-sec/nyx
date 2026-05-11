# Sinatra route with two path captures. Both block formals are bound
# to `:user_id` and `:cmd`; the entry-point seeding pass paints both
# as `Source(UserInput)`. The second formal flows into a `system`
# sink and fires `taint-unsanitised-flow`.
require 'sinatra'

post '/users/:user_id/run/:cmd' do |user_id, cmd|
  system("echo #{user_id}: #{cmd}")
  "ok"
end
