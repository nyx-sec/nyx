// Phase 14 — JUnit test method, benign.

// import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class Benign {
    @Test
    public void testRun() throws Exception {
        System.out.print("__NYX_SINK_HIT__\n");
        // Read + drop payload.
        String unused = System.getenv("NYX_PAYLOAD");
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
