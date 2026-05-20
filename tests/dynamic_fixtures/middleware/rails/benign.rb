# Phase 21 — Rack middleware benign control.
require 'shellwords'

class AuditMiddleware
  def initialize(app)
    @app = app
  end

  def call(env)
    payload = (env['nyx.payload'] || env['QUERY_STRING']).to_s
    system("echo " + Shellwords.escape(payload))
    @app.call(env)
  end
end
