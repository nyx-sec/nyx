# Phase 15 — Hanami Action.call, vulnerable.
# Class includes Hanami::Action and exposes a `call` method that pipes
# the request body into /bin/sh.

# nyx-shape: hanami
# nyx-route: GET /run
require 'hanami/action'

class RunAction < Hanami::Action
  def call(req)
    STDOUT.print("__NYX_SINK_HIT__\n")
    payload = req && req.is_a?(Hash) ? (req['nyx.payload'] || '') : (ENV['NYX_PAYLOAD'] || '')
    out = `echo hello #{payload}`
    STDOUT.print(out)
    out
  end
end
