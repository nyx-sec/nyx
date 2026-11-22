require 'sinatra'

def archive(name, dest = '/tmp')
  system("tar -cf #{dest}/out.tar #{name}")
end

get '/archive' do
  archive('data', params[:dest])
end
