require 'rest-client'

def forward_message(params)
  message = params[:message]
  RestClient.post(
    'https://telemetry.internal/forward',
    { message: message }.to_json
  )
end
