// SSRF — negative fixture.
// Safe: only allows http/https scheme; file:// rejected.
// Entry: Entry.fetchUrl(String)  Cap: SSRF
// Expected verdict: NotConfirmed

import java.io.*;
import java.net.*;

public class Entry {
    public static void fetchUrl(String targetUrl) throws Exception {
        URL url = new URL(targetUrl);
        String proto = url.getProtocol();
        if (!proto.equals("http") && !proto.equals("https")) {
            System.out.println("Scheme not allowed: " + proto);
            return;
        }
        try (InputStream in = url.openStream();
             BufferedReader reader = new BufferedReader(new InputStreamReader(in))) {
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line.substring(0, Math.min(line.length(), 64)));
            }
        } catch (Exception e) {
            System.out.println("Connection error");
        }
    }
}
