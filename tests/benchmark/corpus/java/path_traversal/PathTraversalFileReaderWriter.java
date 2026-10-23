import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;

public class PathTraversalFileReaderWriter {
    public String read(HttpServletRequest request) throws IOException {
        String name = request.getParameter("file");
        try (BufferedReader in = new BufferedReader(new FileReader(name))) {
            return in.readLine();
        }
    }

    public void write(HttpServletRequest request) throws IOException {
        String name = request.getParameter("file");
        try (FileWriter out = new FileWriter(name)) {
            out.write("done");
        }
    }
}
