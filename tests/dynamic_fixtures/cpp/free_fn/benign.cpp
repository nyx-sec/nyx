// Phase 16 — free function with (const char *, size_t), benign.

#include <cstddef>
#include <cstdio>
#include <cstdlib>

void run(const char *payload, std::size_t len) {
    (void)payload; (void)len;
    std::printf("__NYX_SINK_HIT__\n");
    std::fflush(stdout);
    std::system("echo hello");
}
