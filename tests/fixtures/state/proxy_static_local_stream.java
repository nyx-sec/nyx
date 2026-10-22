import java.io.*;

class ProxyStaticLocalStream {
    // Opens and closes a local stream; it does not act on any receiver.
    public static byte[] read(String path) throws IOException {
        FileInputStream in = new FileInputStream(path);
        byte[] data = in.readAllBytes();
        in.close();
        return data;
    }

    public static String first(BufferedReader r) throws IOException {
        String line = r.readLine();
        r.read();
        return line;
    }
}
