// Phase 19 (Track M.1) — class-method benign control for Java.
//
// The payload is passed as an argv element to true(1), so no shell parses or
// echoes marker bytes.
public class Benign {
    public static class UserRepository {
        public UserRepository() {}

        public void findByName(String name) throws Exception {
            Process p = new ProcessBuilder("/usr/bin/true", name)
                .redirectErrorStream(true)
                .start();
            p.waitFor();
        }
    }
}
