import java.io.*;

// The inner stream is closed by try-with-resources; the wrapper built on
// it does not take that responsibility over.  Expected: no resource
// findings.
public class JavaWrapperOverManagedStream {
    interface Sink extends Closeable {
        void write(String s) throws IOException;
    }

    static Sink open(Writer w) {
        return null;
    }

    public void write(String doc, String path) throws IOException {
        Sink sink = null;
        try {
            try (FileOutputStream out = new FileOutputStream(path)) {
                sink = new PrintSink(out, path);
                sink.write(doc);
            }
        } catch (IOException e) {
            throw e;
        } finally {
            try {
                if (sink != null) {
                    sink.close();
                }
            } catch (IOException e) {
                System.err.println(e);
            }
        }
    }

    static class PrintSink implements Sink {
        PrintSink(OutputStream o, String p) {}
        public void write(String s) {}
        public void close() throws IOException {}
    }
}
