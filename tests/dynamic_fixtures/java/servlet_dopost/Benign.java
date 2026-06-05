// Phase 14 — servlet doPost, benign.

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class Benign {
    public void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        System.out.print("__NYX_SINK_HIT__\n");
        String unused = req.getBody();
        if (unused == null) unused = "";
        String[] cmd = {"/bin/sh", "-c", "echo hello"};
        Process p = Runtime.getRuntime().exec(cmd);
        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            resp.write(line + "\n");
        }
        p.waitFor();
    }
}
