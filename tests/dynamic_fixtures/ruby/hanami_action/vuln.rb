# Ruby Hanami Action.call, vulnerable.
# The class imports Hanami::Action and reads the Rack request routed by
# the harness.

# nyx-route: GET /run
require 'hanami/action'
require 'rack/request'

class RunAction < Hanami::Action
  def call(req)
    STDOUT.print("__NYX_SINK_HIT__\n")
    payload = if req.is_a?(Hash)
      Rack::Request.new(req).params['payload'].to_s
    elsif req.respond_to?(:params)
      req.params['payload'].to_s
    else
      ENV['NYX_PAYLOAD'].to_s
    end
    out = `echo hello #{payload}`
    STDOUT.print(out)
    out
  end
end
