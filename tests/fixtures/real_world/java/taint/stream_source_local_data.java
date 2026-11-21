import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.sql.Connection;
import java.util.Properties;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import javax.servlet.http.HttpServletResponse;
import org.springframework.core.io.ClassPathResource;

public class StreamSourceLocalData {
    private Connection conn;

    // Output of a child process is not request input.
    public void processOutput(HttpServletResponse resp) throws IOException {
        Process p = Runtime.getRuntime().exec(new String[] {"uptime"});
        BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line = r.readLine();
        resp.getWriter().println(line);
    }

    public String hostname(String bin) throws Exception {
        Process p = new ProcessBuilder(bin, "-s").start();
        String host = new BufferedReader(new InputStreamReader(p.getInputStream())).readLine();
        conn.createStatement().executeQuery("SELECT * FROM hosts WHERE name = '" + host + "'");
        return host;
    }

    // A classpath resource ships with the application.
    public void schema() throws Exception {
        Properties props = new Properties();
        props.load(new ClassPathResource("app.properties").getInputStream());
        String table = props.getProperty("table");
        conn.createStatement().executeQuery("SELECT * FROM " + table);
    }

    // So does an entry of a zip the application opened itself.
    public void archiveEntry(ZipFile zip, ZipEntry entry) throws Exception {
        InputStream in = zip.getInputStream(entry);
        String cmd = new BufferedReader(new InputStreamReader(in)).readLine();
        Runtime.getRuntime().exec(cmd);
    }
}
