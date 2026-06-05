// Phase 16 — libFuzzer entry, benign.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    (void)data; (void)size;
    std::printf("__NYX_SINK_HIT__\n");
    std::fflush(stdout);
    std::system("echo hello");
    return 0;
}
