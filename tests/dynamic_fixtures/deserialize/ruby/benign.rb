# Phase 03 (Track J.1) — Ruby deserialize benign fixture.
#
# Inspects the marshalled stream's const name before handing it to
# `Marshal.load`; anything outside the tiny allowlist raises before
# any gadget code runs.
ALLOWED = %w[Integer String Array].freeze

def run(blob)
  # Quick const-name sniff — `Marshal` writes the class name as a
  # length-prefixed string after the `o` tag.
  if blob.bytes.any? && !ALLOWED.any? { |c| blob.include?(c) }
    raise ArgumentError, "blocked: non-allowlisted gadget class"
  end
  Marshal.load(blob)
end
