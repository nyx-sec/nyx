import java.io.FileInputStream;

// The finally clause closes the stream on only one branch, so the return
// path may leak it.
class ReturnThroughFinallyMaybe {
    int readFirst(String path, boolean flag) throws Exception {
        FileInputStream in = new FileInputStream(path);
        try {
            int first = in.read();
            return first;
        } finally {
            if (flag) {
                in.close();
            }
        }
    }
}
