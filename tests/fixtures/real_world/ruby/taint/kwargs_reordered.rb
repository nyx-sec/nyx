require 'sinatra'

def run_report(name, dir: '.', mode: 'r')
  system("cat #{dir}/#{name} #{mode}")
end

get '/report' do
  run_report('latest', mode: 'w', dir: params[:dir])
end
