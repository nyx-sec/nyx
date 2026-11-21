import java.io.FileInputStream;

// The finally clause runs on the return path but never closes the stream.
public class VulnReturnInTryNoCloseInFinally {
    public int firstByte(String path) throws Exception {
        FileInputStream in = new FileInputStream(path);
        try {
            int first = in.read();
            return first;
        } finally {
            System.out.println("done");
        }
    }
}
