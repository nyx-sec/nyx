import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class UrlConnectionNotCloseable {
    public String viaTryWithResources() throws IOException {
        URL url = new URL("https://api.example.com/x");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        try (InputStream in = conn.getInputStream()) {
            return new String(in.readAllBytes());
        }
    }

    public String viaDisconnect() throws IOException {
        URL url = new URL("https://api.example.com/y");
        HttpURLConnection c = (HttpURLConnection) url.openConnection();
        try (InputStream in = c.getInputStream()) {
            return new String(in.readAllBytes());
        } finally {
            c.disconnect();
        }
    }

    public int stillLeaks(String path) throws IOException {
        FileInputStream fis = new FileInputStream(path);
        return fis.read();
    }
}
