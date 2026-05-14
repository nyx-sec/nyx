// Phase 14 — servlet doGet, benign.
//
// Reads `payload` from the request but never threads it into a
// shell-interpreted slot; the cmdi marker cannot fire.

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class Benign {
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        System.out.print("__NYX_SINK_HIT__\n");
        // Read + drop the parameter.
        String unused = req.getParameter("payload");
        if (unused == null) unused = "";
        String[] cmd = {"/bin/sh", "-c", "echo hello"};
        Process p = Runtime.getRuntime().exec(cmd);
        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }
        p.waitFor();
    }
}
