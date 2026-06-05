// Phase 14 — servlet doGet, vulnerable.
//
// Reads the `payload` query parameter from the request stub and feeds
// it through `/bin/sh -c` — payload `; echo NYX_PWN_CMDI` fires the
// cmdi oracle marker.

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class Vuln {
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        System.out.print("__NYX_SINK_HIT__\n");
        String input = req.getParameter("payload");
        if (input == null) input = "";
        String[] cmd = {"/bin/sh", "-c", "echo hello " + input};
        Process p = Runtime.getRuntime().exec(cmd);
        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            resp.write(line + "\n");
        }
        p.waitFor();
    }
}
