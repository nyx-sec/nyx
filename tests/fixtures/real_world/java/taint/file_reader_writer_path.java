import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;

public class FileReaderWriterPath {
    public String read(HttpServletRequest req) throws IOException {
        String name = req.getParameter("file");
        try (BufferedReader in = new BufferedReader(new FileReader(name))) {
            return in.readLine();
        }
    }

    public void write(HttpServletRequest req) throws IOException {
        String name = req.getParameter("file");
        try (FileWriter out = new FileWriter(name)) {
            out.write("done");
        }
    }

    public String readFixed() throws IOException {
        try (BufferedReader in = new BufferedReader(new FileReader("/etc/app/motd"))) {
            return in.readLine();
        }
    }

    public void writeFixed(HttpServletRequest req) throws IOException {
        String body = req.getParameter("body");
        try (FileWriter out = new FileWriter("/var/log/app/last-body.txt")) {
            out.write("ok");
        }
    }
}
