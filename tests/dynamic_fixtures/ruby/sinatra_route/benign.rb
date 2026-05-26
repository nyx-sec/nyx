# Ruby Sinatra route, benign.
# Validates the real path-capture parameter before running a fixed echo.

require 'sinatra/base'

class NyxSinatraApp < Sinatra::Base
  set :environment, :test
  disable :run

  get '/run/:payload' do |payload|
    unless payload =~ /\A[A-Za-z0-9]{1,32}\z/
      STDOUT.print("invalid\n")
      "invalid"
    else
      out = `echo hello`
      STDOUT.print(out)
      out
    end
  end
end
