# Ruby Sinatra route, vulnerable.
# Reads a real path-capture parameter from Sinatra and pipes it through /bin/sh.

require 'sinatra/base'

class NyxSinatraApp < Sinatra::Base
  set :environment, :test
  disable :run

  get '/run/:payload' do |payload|
    STDOUT.print("__NYX_SINK_HIT__\n")
    out = `echo hello #{payload}`
    STDOUT.print(out)
    out
  end
end
