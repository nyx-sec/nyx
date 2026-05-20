// Phase 19 (Track M.1) — class-method benign control for C++.
#include <unistd.h>
#include <sys/wait.h>
#include <string>

class UserService {
public:
    UserService() = default;
    void run(const std::string& input) {
        pid_t pid = fork();
        if (pid == 0) {
            const char* argv[] = { "/bin/echo", input.c_str(), nullptr };
            execv("/bin/echo", const_cast<char* const*>(argv));
            _exit(127);
        }
        int status = 0;
        waitpid(pid, &status, 0);
    }
};
