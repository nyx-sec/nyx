// Phase 11 (Track J.9) — Java DATA_EXFIL benign control fixture.
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Set;

public class Benign {
    private static final Set<String> ALLOWLIST = Set.of("127.0.0.1", "localhost");

    public static void run(String host) throws Exception {
        if (!ALLOWLIST.contains(host)) return;
        URL url = new URL("http://" + host + "/exfil?token=alice-creds");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.connect();
        conn.disconnect();
    }
}
