import java.io.FileInputStream;

// The finally clause runs on the return path but never closes the stream:
// the leak is still reported.
class ReturnThroughFinallyLeak {
    int readFirst(String path) throws Exception {
        FileInputStream in = new FileInputStream(path);
        try {
            int first = in.read();
            return first;
        } finally {
            System.out.println("done");
        }
    }
}
