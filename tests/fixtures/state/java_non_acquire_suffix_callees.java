import java.net.*;
import javax.net.SocketFactory;

// closeSocket is not an acquire; createSocket is.
// Expected: exactly one state-resource-leak (dial).
public class JavaNonAcquireSuffix {
    public static void shut(Helper h) {
        Object r = h.closeSocket();
        System.out.println(r);
    }

    public static int dial(SocketFactory sf, String host) throws Exception {
        Socket s = sf.createSocket(host, 443);
        return s.getPort();
    }

    interface Helper {
        Object closeSocket();
    }
}
