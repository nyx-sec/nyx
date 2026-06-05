# Phase 15 — Rack middleware, vulnerable.
# `call(env)` reads env['nyx.payload'] and pipes to /bin/sh -c.

class NyxRackApp
  def initialize(app = nil); @app = app; end

  def call(env)
    STDOUT.print("__NYX_SINK_HIT__\n")
    payload = env['nyx.payload'] || ENV['NYX_PAYLOAD'] || ''
    out = `echo hello #{payload}`
    STDOUT.print(out)
    [200, { 'Content-Type' => 'text/plain' }, [out]]
  end
end
