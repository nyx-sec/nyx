// Phase 08 (Track J.6) — Java raw-socket HEADER_INJECTION vuln fixture.
//
// Writes the response status line and headers directly to the wire via
// `OutputStream.write(byte[])` against the `java.net.Socket` returned
// by `ServerSocket.accept()`, bypassing the framework-level CRLF
// validator that Tomcat / Jetty / Undertow would otherwise interpose
// on `HttpServletResponse.setHeader`.  A payload carrying
// `\r\nSet-Cookie: ...` splits the single Set-Cookie header into two
// on the wire, producing the canonical smuggled-second-header shape
// that `ProbeKind::HeaderWireFrame` is designed to catch.
//
// The harness (`src/dynamic/lang/java.rs::emit_header_injection_harness`)
// detects the `java.net.ServerSocket` + `setCookieValue` tokens in
// this file and routes through the tier-(b) wire-frame branch: bind
// a loopback `ServerSocket` via `createServer`, accept one client
// (`runOnce`) on a worker thread, issue one raw-socket
// `GET / HTTP/1.0` from the harness, read the bytes the fixture
// wrote to the response socket up to the CRLF-CRLF boundary, and
// emit them as a `ProbeKind::HeaderWireFrame` record.
//
// All three entry points are `public static` so the harness can
// resolve them via `Class.forName("Vuln").getDeclaredMethod(...)`
// reflective dispatch (same pattern as Phase 06 LDAP Java tier-(b)).
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class Vuln {
    // Bytes go straight onto the wire with no encoding pass.  The
    // harness installs the cookie value before booting the accept
    // loop, mirroring the Python `Handler.cookie_value` and Ruby
    // `set_cookie_value` setters.
    private static byte[] nyxCookieValue = new byte[0];

    public static void setCookieValue(byte[] value) {
        nyxCookieValue = (value == null) ? new byte[0] : value;
    }

    public static ServerSocket createServer() throws IOException {
        return new ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1"));
    }

    public static void runOnce(ServerSocket server) {
        Socket client = null;
        try {
            server.setSoTimeout(5000);
            client = server.accept();
            client.setSoTimeout(1000);
            // Drain whatever request bytes the client sent so the
            // kernel does not stall the write that follows.  Ignore
            // read errors — the client may have already shut its
            // write side.
            try {
                InputStream in = client.getInputStream();
                byte[] buf = new byte[4096];
                int read = in.read(buf, 0, buf.length);
                // discard
                if (read < 0) {
                    // EOF, nothing to drain
                }
            } catch (IOException ignored) {
                // ignore drain errors
            }
            byte[] body = "ok\n".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
            java.io.ByteArrayOutputStream raw = new java.io.ByteArrayOutputStream();
            raw.write("HTTP/1.0 200 OK\r\n".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
            raw.write(("Content-Length: " + body.length + "\r\n")
                .getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
            raw.write("Set-Cookie: ".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
            raw.write(nyxCookieValue);
            raw.write("\r\n\r\n".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
            raw.write(body);
            OutputStream out = client.getOutputStream();
            out.write(raw.toByteArray());
            out.flush();
        } catch (IOException e) {
            // ignore — harness will time out reading and fall back
        } finally {
            if (client != null) {
                try { client.close(); } catch (IOException ignored) {}
            }
        }
    }
}
