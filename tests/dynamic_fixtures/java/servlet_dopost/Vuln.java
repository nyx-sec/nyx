// Phase 14 — servlet doPost, vulnerable.
//
// Reads the POST body from the request stub and feeds it through
// `/bin/sh -c`.

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class Vuln {
    public void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        System.out.print("__NYX_SINK_HIT__\n");
        String input = req.getBody();
        if (input == null) input = "";
        String[] cmd = {"/bin/sh", "-c", "echo hello " + input};
        Process p = Runtime.getRuntime().exec(cmd);
        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }
        p.waitFor();
    }
}
