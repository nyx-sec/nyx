require 'sinatra'

get '/a' do
  system('sh', '-c', params[:cmd])
end

get '/b' do
  exec('bash', '-c', params[:cmd])
end

get '/c' do
  system('cmd.exe', '/c', params[:cmd])
end

get '/d' do
  system({ 'A' => '1' }, 'env', 'bash', '-c', params[:cmd])
end

get '/e' do
  system(params[:tool], '--version')
end
