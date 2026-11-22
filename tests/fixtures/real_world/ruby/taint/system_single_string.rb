require 'sinatra'

get '/log' do
  ref = params[:ref]
  system("git log #{ref}")
end
