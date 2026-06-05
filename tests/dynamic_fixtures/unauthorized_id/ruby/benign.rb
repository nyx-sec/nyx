# Phase 11 (Track J.9) — Ruby UNAUTHORIZED_ID benign control fixture.
STORE = { "alice" => { email: "alice@x" }, "bob" => { email: "bob@x" } }.freeze
CALLER_ID = "alice"

def run(owner_id)
  return nil unless owner_id == CALLER_ID
  STORE[owner_id]
end
