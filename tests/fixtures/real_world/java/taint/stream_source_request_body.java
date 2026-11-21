import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import javax.servlet.http.HttpServletRequest;

public class StreamSourceRequestBody {
    // Request body through a wrapped input stream.
    public void viaInputStream(HttpServletRequest request) throws IOException {
        BufferedReader r = new BufferedReader(new InputStreamReader(request.getInputStream()));
        String line = r.readLine();
        Runtime.getRuntime().exec(line);
    }

    // Request body through getReader().
    public void viaReader(HttpServletRequest request) throws IOException {
        BufferedReader r = request.getReader();
        String line = r.readLine();
        Runtime.getRuntime().exec(line);
    }

    // A socket is network input.
    public void viaSocket(Socket sock) throws IOException {
        BufferedReader r = new BufferedReader(new InputStreamReader(sock.getInputStream()));
        String line = r.readLine();
        Runtime.getRuntime().exec(line);
    }

    // File content is a source in the engine's model (Medium, file data).
    public void viaConfigFile() throws IOException {
        BufferedReader br = new BufferedReader(new FileReader("/etc/app/hosts"));
        String host = br.readLine();
        Runtime.getRuntime().exec("ping " + host);
    }

    // Standard input.
    public void viaStdin() throws IOException {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String cmd = in.readLine();
        Runtime.getRuntime().exec(cmd);
    }
}
