require 'sinatra'

def run_report(name, dir: '.', mode: 'r')
  system("cat #{dir}/#{name}")
end

get '/report' do
  run_report('latest', mode: params[:mode], dir: '/var/reports')
end
