// Benign control for recursive C++ class-method receiver construction.
#include <string>

class ShellRunner {
public:
    void exec(const std::string& _cmd) {}
};

class CommandRunner {
    ShellRunner shell;

public:
    explicit CommandRunner(ShellRunner shell) : shell(shell) {}

    void run(const std::string& input) {
        shell.exec(input);
    }
};

class UserService {
    CommandRunner runner;

public:
    explicit UserService(CommandRunner runner) : runner(runner) {}

    void run(const std::string& input) {
        runner.run(input);
    }
};
