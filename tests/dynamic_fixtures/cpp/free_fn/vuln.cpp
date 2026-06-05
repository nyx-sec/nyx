// Phase 16 — free function with (const char *, size_t), vulnerable.
// Cap: CODE_EXEC.

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <string>

void run(const char *payload, std::size_t len) {
    std::printf("__NYX_SINK_HIT__\n");
    std::fflush(stdout);
    if (!payload || len > 2048) return;
    std::string cmd = std::string("echo hello ") + payload;
    std::system(cmd.c_str());
}
