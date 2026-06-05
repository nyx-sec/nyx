# Phase 08 (Track J.6) — Ruby raw-socket HEADER_INJECTION vuln fixture.
#
# Writes the response status line and headers directly to the wire via
# `socket.write`, bypassing the framework-level CRLF validator that
# Rack / Sinatra / Rails would otherwise interpose.  A payload carrying
# `\r\nSet-Cookie: ...` splits the single Set-Cookie header into two on
# the wire, producing the canonical smuggled-second-header shape that
# `ProbeKind::HeaderWireFrame` is designed to catch.
#
# The harness (`src/dynamic/lang/ruby.rs::emit_header_injection_harness`)
# detects the `TCPServer.new` token in this file and routes through the
# tier-(b) wire-frame branch: bind a loopback `TCPServer` via
# `create_server`, accept one client (`run_once`), issue one raw
# `GET / HTTP/1.0` from the harness, read the bytes the fixture wrote
# to the response socket up to the CRLF-CRLF boundary, and emit them
# as a `ProbeKind::HeaderWireFrame` record.
require 'socket'

# Bytes go straight onto the wire with no encoding pass.  The harness
# installs the cookie value before booting the accept loop, mirroring
# the JS `setCookieValue` and Python `Handler.cookie_value =` setters.
$nyx_cookie_value = String.new(encoding: 'BINARY')

def set_cookie_value(value)
  $nyx_cookie_value = value.respond_to?(:b) ? value.b : value.to_s.b
end

def create_server
  TCPServer.new('127.0.0.1', 0)
end

def run_once(server)
  socket = server.accept
  begin
    socket.recv(4096)
  rescue StandardError
    # ignore client-side read errors
  end
  body = "ok\n".b
  raw = String.new(encoding: 'BINARY')
  raw << "HTTP/1.0 200 OK\r\n".b
  raw << "Content-Length: #{body.bytesize}\r\n".b
  raw << "Set-Cookie: ".b
  raw << $nyx_cookie_value
  raw << "\r\n\r\n".b
  raw << body
  socket.write(raw)
ensure
  begin
    socket.close if socket
  rescue StandardError
    # ignore close errors
  end
end
