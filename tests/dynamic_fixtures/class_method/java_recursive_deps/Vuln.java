// Class-method fixture with recursively constructed Java dependencies.
import java.io.InputStream;

public class Vuln {
    public static class ShellRunner {
        public String run(String command) throws Exception {
            Process p = new ProcessBuilder("sh", "-c", "true " + command)
                .redirectErrorStream(true)
                .start();
            try (InputStream in = p.getInputStream()) {
                return new String(in.readAllBytes());
            }
        }
    }

    public static class UserRepository {
        private final ShellRunner shellRunner;

        public UserRepository(ShellRunner shellRunner) {
            this.shellRunner = shellRunner;
        }

        public String find(String input) throws Exception {
            return shellRunner.run(input);
        }
    }

    public static class UserService {
        private final UserRepository userRepository;

        public UserService(UserRepository userRepository) {
            this.userRepository = userRepository;
        }

        public String run(String input) throws Exception {
            return userRepository.find(input);
        }
    }
}
