// Benign control for recursively constructed Java dependencies.
public class Benign {
    public static class ShellRunner {
        public String run(String command) {
            return command.replace("NYX_PWN", "");
        }
    }

    public static class UserRepository {
        private final ShellRunner shellRunner;

        public UserRepository(ShellRunner shellRunner) {
            this.shellRunner = shellRunner;
        }

        public String find(String input) {
            return shellRunner.run(input);
        }
    }

    public static class UserService {
        private final UserRepository userRepository;

        public UserService(UserRepository userRepository) {
            this.userRepository = userRepository;
        }

        public String run(String input) {
            return userRepository.find(input);
        }
    }
}
