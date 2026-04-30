require 'rest-client'

# DATA_EXFIL safe: plain user input echoed into a RestClient.post body
# at a fixed destination URL must not fire. Sensitivity-gate strips the
# cap for Plain-tier sources.
def forward_message(params)
  message = params[:message]
  RestClient.post(
    'https://telemetry.internal/forward',
    { message: message }.to_json
  )
end
