import java.io.DataOutputStream;
import java.io.PrintStream;

public class PrintlnNonResponseStream {
    public PrintStream stderr;
    private DataOutputStream peer;

    int run(String id) throws Exception {
        try {
            Integer.parseInt(id);
        } catch (Exception e) {
            String msg = id + ": " + e.getMessage();
            stderr.println(msg);
            return 1;
        }
        return 0;
    }

    void greet(javax.servlet.http.HttpServletRequest req) throws Exception {
        String who = req.getParameter("who");
        peer.writeUTF(who);
        peer.write(who.getBytes());
    }
}
