import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import javax.servlet.http.HttpServletResponse;

public class SafeProcessOutputStream {
    public void uptime(HttpServletResponse response) throws IOException {
        Process p = new ProcessBuilder("uptime").start();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
            String line = r.readLine();
            response.getWriter().println(line);
        }
    }
}
