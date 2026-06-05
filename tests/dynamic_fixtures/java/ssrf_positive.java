// SSRF — positive fixture.
// Vulnerable: makes a request to a user-controlled URL.
// Entry: Entry.fetchUrl(String)  Cap: SSRF
// Expected verdict: Confirmed (file:///etc/passwd → "daemon:" in output)
// Note: Java URL supports file:// scheme natively.

import java.io.*;
import java.net.*;

public class Entry {
    public static void fetchUrl(String targetUrl) throws Exception {
        System.out.print("__NYX_SINK_HIT__\n");
        URL url = new URL(targetUrl);
        try (InputStream in = url.openStream();
             BufferedReader reader = new BufferedReader(new InputStreamReader(in))) {
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
        } catch (Exception e) {
            // silent
        }
    }
}
