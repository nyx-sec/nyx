// SPDX-License-Identifier: GPL-3.0-or-later
//
// Long-lived javac worker bundled with nyx-scanner.  The Rust pool side
// compiles + spawns this once per toolchain id; subsequent harness
// compiles run in-process via ToolProvider#getSystemJavaCompiler so the
// JVM cold-start cost is amortised across every harness in a verify run.
//
// Wire format: newline-terminated UTF-8 JSON, one request per line:
//     {"id":"0","cwd":"/path/to/workdir","args":["-d","/tmp/x","Foo.java"]}\n
//
// Response: newline-terminated UTF-8 JSON, one per request:
//     {"id":"0","success":true,"stderr_b64":"<base64 of javac stderr>"}\n
//
// stderr is base64-encoded so it never embeds raw newlines or quotes
// inside the JSON envelope -- keeps the parser on both sides tiny.

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;

public class NyxJavacWorker {
    public static void main(String[] argv) throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            // JRE without javac (rare on dev boxes, possible on slim CI
            // images). Signal the Rust side so it falls back to the
            // direct-spawn legacy path.
            System.err.println("nyx-javac-worker: no system Java compiler (JRE-only install?)");
            System.exit(2);
        }
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        PrintStream out = new PrintStream(System.out, true, StandardCharsets.UTF_8);
        // Banner line. The Rust side reads this first so it knows the
        // worker is live before it queues any compile requests.
        out.println("{\"ready\":true}");
        out.flush();

        String line;
        while ((line = in.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty()) continue;
            Request req;
            try {
                req = parse(line);
            } catch (Throwable t) {
                // Malformed request -- emit an error response keyed on
                // an empty id so the Rust side can at least surface it.
                writeResponse(out, "", false, ("nyx-javac-worker: parse error: " + t.getMessage()).getBytes(StandardCharsets.UTF_8));
                continue;
            }
            ByteArrayOutputStream errBuf = new ByteArrayOutputStream();
            PrintStream errStream = new PrintStream(errBuf, true, StandardCharsets.UTF_8);
            int rc;
            try {
                String[] args = req.args.toArray(new String[0]);
                if (req.cwd != null && !req.cwd.isEmpty()) {
                    // The JDK compiler API has no per-task cwd switch,
                    // so we rewrite relative args. The harness build
                    // already supplies absolute paths via the Rust side,
                    // but we still set user.dir defensively so any
                    // relative -d / -cp / source-path entries resolve
                    // against the requested workdir rather than the
                    // worker JVM's launch directory.
                    System.setProperty("user.dir", req.cwd);
                }
                rc = compiler.run(null, null, errStream, args);
            } catch (Throwable t) {
                t.printStackTrace(errStream);
                rc = 1;
            }
            boolean success = (rc == 0);
            writeResponse(out, req.id, success, errBuf.toByteArray());
        }
    }

    private static void writeResponse(PrintStream out, String id, boolean success, byte[] stderr) {
        String b64 = Base64.getEncoder().encodeToString(stderr);
        StringBuilder sb = new StringBuilder(64 + b64.length());
        sb.append("{\"id\":");
        appendJsonString(sb, id);
        sb.append(",\"success\":").append(success);
        sb.append(",\"stderr_b64\":\"").append(b64).append("\"}");
        out.println(sb);
        out.flush();
    }

    private static void appendJsonString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '"': sb.append("\\\""); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
    }

    private static final class Request {
        String id = "";
        String cwd = "";
        List<String> args = new ArrayList<>();
    }

    private static Request parse(String s) {
        Parser p = new Parser(s);
        Request r = new Request();
        p.skipWs();
        p.expect('{');
        p.skipWs();
        if (p.peek() == '}') {
            p.next();
            return r;
        }
        while (true) {
            p.skipWs();
            String key = p.parseString();
            p.skipWs();
            p.expect(':');
            p.skipWs();
            if (key.equals("id")) {
                r.id = p.parseString();
            } else if (key.equals("cwd")) {
                r.cwd = p.parseString();
            } else if (key.equals("args")) {
                p.expect('[');
                p.skipWs();
                if (p.peek() != ']') {
                    while (true) {
                        p.skipWs();
                        r.args.add(p.parseString());
                        p.skipWs();
                        if (p.peek() == ',') { p.next(); continue; }
                        break;
                    }
                }
                p.skipWs();
                p.expect(']');
            } else {
                skipValue(p);
            }
            p.skipWs();
            if (p.peek() == ',') { p.next(); continue; }
            break;
        }
        p.skipWs();
        p.expect('}');
        return r;
    }

    private static void skipValue(Parser p) {
        p.skipWs();
        char c = p.peek();
        if (c == '"') { p.parseString(); }
        else if (c == '[') {
            p.next();
            p.skipWs();
            if (p.peek() != ']') {
                while (true) {
                    skipValue(p); p.skipWs();
                    if (p.peek() == ',') { p.next(); continue; }
                    break;
                }
            }
            p.skipWs();
            p.expect(']');
        } else if (c == '{') {
            p.next();
            p.skipWs();
            if (p.peek() != '}') {
                while (true) {
                    p.skipWs();
                    p.parseString();
                    p.skipWs();
                    p.expect(':');
                    skipValue(p);
                    p.skipWs();
                    if (p.peek() == ',') { p.next(); continue; }
                    break;
                }
            }
            p.skipWs();
            p.expect('}');
        } else {
            int start = p.pos;
            while (p.pos < p.s.length() && "0123456789.-+eEtrufalsn".indexOf(p.s.charAt(p.pos)) >= 0) {
                p.pos++;
            }
            if (p.pos == start) {
                throw new RuntimeException("bad value at " + p.pos);
            }
        }
    }

    private static final class Parser {
        final String s; int pos = 0;
        Parser(String s) { this.s = s; }
        char peek() { return s.charAt(pos); }
        char next() { return s.charAt(pos++); }
        void skipWs() { while (pos < s.length() && Character.isWhitespace(s.charAt(pos))) pos++; }
        void expect(char c) {
            if (pos >= s.length() || s.charAt(pos) != c) {
                throw new RuntimeException("expected '" + c + "' at " + pos + " of " + s);
            }
            pos++;
        }
        String parseString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (pos < s.length()) {
                char c = s.charAt(pos++);
                if (c == '"') return sb.toString();
                if (c == '\\') {
                    char e = s.charAt(pos++);
                    switch (e) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'u': {
                            String hex = s.substring(pos, pos + 4);
                            pos += 4;
                            sb.append((char) Integer.parseInt(hex, 16));
                            break;
                        }
                        default: throw new RuntimeException("bad escape \\" + e);
                    }
                } else {
                    sb.append(c);
                }
            }
            throw new RuntimeException("unterminated string");
        }
    }
}
