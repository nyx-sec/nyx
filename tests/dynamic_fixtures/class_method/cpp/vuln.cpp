// Phase 19 (Track M.1) — class-method vuln fixture for C++.
//
// UserService::run pipes user input into `system(3)`.  Default
// constructor exists; the harness can build the receiver with
// `UserService instance;`.
#include <cstdlib>
#include <string>

class UserService {
public:
    UserService() = default;
    void run(const std::string& input) {
        std::string cmd = std::string("echo ") + input;
        // SINK: tainted input → system(3)
        std::system(cmd.c_str());
    }
};
