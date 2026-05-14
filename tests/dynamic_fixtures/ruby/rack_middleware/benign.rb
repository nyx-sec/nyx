# Phase 15 — Rack middleware, benign.

class NyxRackApp
  def initialize(app = nil); @app = app; end

  def call(env)
    payload = env['nyx.payload'] || ENV['NYX_PAYLOAD'] || ''
    unless payload =~ /\A[A-Za-z0-9]{1,32}\z/
      [400, { 'Content-Type' => 'text/plain' }, ['invalid']]
    else
      out = `echo hello`
      STDOUT.print(out)
      [200, { 'Content-Type' => 'text/plain' }, [out]]
    end
  end
end
