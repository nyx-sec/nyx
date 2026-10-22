import java.io.*;

class UacHandleNameArgs {
    // The closed stream is only described, not read.
    void describe(String p, OutputStream out) throws IOException {
        FileInputStream in = new FileInputStream(p);
        in.close();
        out.write(in.toString().getBytes());
    }
}
