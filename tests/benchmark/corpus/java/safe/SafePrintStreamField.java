import java.io.PrintStream;

public class SafePrintStreamField {
    public PrintStream stderr;

    int run(String id) {
        try {
            Integer.parseInt(id);
        } catch (Exception e) {
            String msg = id + ": " + e.getMessage();
            stderr.println(msg);
            return 1;
        }
        return 0;
    }
}
