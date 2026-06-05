# Ruby Hanami Action.call, benign.
# Validates the real request parameter before running a fixed echo.

# nyx-route: GET /run
require 'hanami/action'
require 'rack/request'

class RunAction < Hanami::Action
  def call(req)
    payload = if req.is_a?(Hash)
      Rack::Request.new(req).params['payload'].to_s
    elsif req.respond_to?(:params)
      req.params['payload'].to_s
    else
      ENV['NYX_PAYLOAD'].to_s
    end
    unless payload =~ /\A[A-Za-z0-9]{1,32}\z/
      STDOUT.print("invalid\n")
      return "invalid"
    end
    out = `echo hello`
    STDOUT.print(out)
    out
  end
end
