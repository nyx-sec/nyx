// C++ class-method fixture whose receiver has same-file constructor
// dependencies but no default constructor.
#include <cstdlib>
#include <string>

class ShellRunner {
public:
    void exec(const std::string& cmd) {
        std::system(cmd.c_str());
    }
};

class CommandRunner {
    ShellRunner shell;

public:
    explicit CommandRunner(ShellRunner shell) : shell(shell) {}

    void run(const std::string& input) {
        shell.exec(std::string("true ") + input);
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
