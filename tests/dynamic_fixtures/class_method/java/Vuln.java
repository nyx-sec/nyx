// Phase 19 (Track M.1) — class-method vuln fixture for Java.
//
// UserRepository.findByName concatenates user input into a shell command.
// The nested class has a default constructor so the ClassMethod harness can
// build the receiver reflectively.
import java.io.InputStream;

public class Vuln {
    public static class UserRepository {
        public UserRepository() {}

        public void findByName(String name) throws Exception {
            Process p = new ProcessBuilder("sh", "-c", "true " + name)
                .redirectErrorStream(true)
                .start();
            try (InputStream in = p.getInputStream()) {
                in.transferTo(System.out);
            }
            p.waitFor();
        }
    }
}
