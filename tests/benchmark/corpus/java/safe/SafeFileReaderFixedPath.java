import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;

public class SafeFileReaderFixedPath {
    public String motd() throws IOException {
        try (BufferedReader in = new BufferedReader(new FileReader("/etc/app/motd"))) {
            return in.readLine();
        }
    }

    public void audit(HttpServletRequest request) throws IOException {
        String note = request.getParameter("note");
        try (FileWriter out = new FileWriter("/var/log/app/audit.txt")) {
            out.write("ok");
        }
    }
}
