# Phase 15 — Hanami Action.call, benign.
# Validates payload before running the fixed echo.

# nyx-shape: hanami
# nyx-route: GET /run
require 'hanami/action'

class RunAction < Hanami::Action
  def call(req)
    payload = req && req.is_a?(Hash) ? (req['nyx.payload'] || '') : (ENV['NYX_PAYLOAD'] || '')
    unless payload =~ /\A[A-Za-z0-9]{1,32}\z/
      STDOUT.print("invalid\n")
      return "invalid"
    end
    out = `echo hello`
    STDOUT.print(out)
    out
  end
end
