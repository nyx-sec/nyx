// Phase 14 — JUnit test method, vulnerable.
//
// The `org.junit.jupiter.api` comment marker tells the Phase 14 shape
// detector to select `JavaShape::JunitTest`; the actual annotation is
// the fixture-local `@NyxTest` stub so the file compiles under a
// dependency-free javac invocation.

// import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class Vuln {
    @Test
    public void testRun() throws Exception {
        System.out.print("__NYX_SINK_HIT__\n");
        String input = System.getenv("NYX_PAYLOAD");
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
