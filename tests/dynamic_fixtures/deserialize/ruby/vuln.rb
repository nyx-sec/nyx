# Phase 03 (Track J.1) — Ruby deserialize vuln fixture.
#
# `Marshal.load` materialises arbitrary constants; a CVE-class gadget
# in the payload runs through `_load` / `_load_data` without any
# allowlist check.
def run(blob)
  Marshal.load(blob)
end
