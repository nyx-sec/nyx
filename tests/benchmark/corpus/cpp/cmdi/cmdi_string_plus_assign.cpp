#include <cstdlib>
#include <string>

// Appending a literal flag with `+=` keeps the environment value in `cmd`.
int main() {
    std::string cmd = getenv("USER_CMD");
    cmd += " --verbose";
    system(cmd.c_str());
    return 0;
}
