import java.io.*;

class ProxyReceiverFieldLeak {
    private FileInputStream in;

    void start(String p) throws IOException {
        in = new FileInputStream(p);
    }

    void stop() throws IOException {
        in.close();
    }

    // start() opens a stream into the receiver; nothing calls stop().
    static int leaks(String p) throws IOException {
        ProxyReceiverFieldLeak h = new ProxyReceiverFieldLeak();
        h.start(p);
        return 1;
    }
}
