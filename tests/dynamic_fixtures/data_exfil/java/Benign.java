// Phase 11 (Track J.9) — Java DATA_EXFIL benign control fixture.
//
// Models a hardened outbound HTTP call that gates the destination host
// through a loopback allowlist before issuing the request.  The harness
// reflectively invokes `run(payload)`; non-allowlist payloads (e.g.
// `attacker.test`) short-circuit before `NyxMockHttp.get(url)` so the
// captured-hosts list stays empty for the differential runner and no
// probe is emitted, clearing `OutboundHostNotIn` for the attacker
// payload.  Loopback payloads (e.g. `127.0.0.1`) reach the helper but
// the captured host is inside the allowlist so the predicate stays
// clear there too.
import java.util.Set;

public class Benign {
    private static final Set<String> ALLOWLIST = Set.of("127.0.0.1", "localhost");

    public static void run(String host) throws Exception {
        if (!ALLOWLIST.contains(host)) return;
        NyxMockHttp.get("http://" + host + "/exfil?token=alice-creds");
    }
}
