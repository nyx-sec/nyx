import java.io.FileWriter;

public class SafePrintStreamField {
    public FileWriter log;

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
}
