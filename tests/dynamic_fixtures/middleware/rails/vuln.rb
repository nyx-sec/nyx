# Phase 21 (Track M.3) — Rack/Rails middleware vuln fixture.
#
# `AuditMiddleware#call(env)` splices `env['nyx.payload']` into a shell
# command — classic Rack-middleware cmdi shape.

class AuditMiddleware
  def initialize(app)
    @app = app
  end

  def call(env)
    payload = env['nyx.payload'] || env['QUERY_STRING'].to_s
    # SINK: tainted env value concatenated into shell command.
    system("echo " + payload.to_s)
    @app.call(env)
  end
end
