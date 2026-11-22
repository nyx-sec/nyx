require 'sinatra'

get '/log' do
  ref = params[:ref]
  system({ 'GIT_PAGER' => 'cat' }, 'git', 'log', ref, chdir: '/srv/repo')
  exec('ls', '-l', ref)
end
