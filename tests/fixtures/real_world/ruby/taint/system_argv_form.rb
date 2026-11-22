require 'sinatra'

get '/log' do
  ref = params[:ref]
  system('git', 'log', ref)
  system('git', 'log', ref, chdir: '/srv/repo')
end
