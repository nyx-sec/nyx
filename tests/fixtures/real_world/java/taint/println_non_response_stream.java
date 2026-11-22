import java.io.ByteArrayOutputStream;
import java.io.FileWriter;

public class PrintlnNonResponseStream {
    public FileWriter log;
    private ByteArrayOutputStream buf;

    int run(String id) throws Exception {
        try {
            Integer.parseInt(id);
        } catch (Exception e) {
            String msg = id + ": " + e.getMessage();
            log.write(msg);
            return 1;
        }
        return 0;
    }

    void greet(javax.servlet.http.HttpServletRequest req) throws Exception {
        String who = req.getParameter("who");
        buf.write(who.getBytes());
    }
}
