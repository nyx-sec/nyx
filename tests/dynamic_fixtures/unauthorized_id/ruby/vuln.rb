# Phase 11 (Track J.9) — Ruby UNAUTHORIZED_ID vuln fixture.
STORE = { "alice" => { email: "alice@x" }, "bob" => { email: "bob@x" } }.freeze
CALLER_ID = "alice"

def run(owner_id)
  STORE[owner_id]
end
