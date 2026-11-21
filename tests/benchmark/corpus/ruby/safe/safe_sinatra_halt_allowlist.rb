require 'sinatra'

ALLOWED = %w[ls pwd].freeze

get '/run' do
  cmd = params[:cmd]
  unless ALLOWED.include?(cmd)
    halt 400, 'bad command'
  end
  `#{cmd}`
end
