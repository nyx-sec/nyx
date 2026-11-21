import java.io.IOException;

public class SafeRuntimeExecLiteral {
    public void restart(String reason) throws IOException {
        Runtime.getRuntime().exec("systemctl restart app");
    }
}
