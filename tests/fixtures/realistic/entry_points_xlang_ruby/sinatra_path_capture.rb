# Ruby Sinatra entry-kind seeding precision. The `get` route binds
# `name` as a path capture; the entry-point seeding pass paints `name`
# as `Source(UserInput)`, producing `taint-unsanitised-flow` at the
# `system` sink. Without per-formal route-capture gating the engine
# fell back to `cfg-unguarded-sink` for Sinatra block formals.
require 'sinatra'

get '/run/:name' do |name|
  system("echo #{name}")
  "ok"
end
