// Phase 16 — libFuzzer entry, vulnerable. Cap: CODE_EXEC.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::printf("__NYX_SINK_HIT__\n");
    std::fflush(stdout);
    if (size == 0 || size > 2048) return 0;
    std::string payload(reinterpret_cast<const char*>(data), size);
    std::string cmd = std::string("echo hello ") + payload;
    std::system(cmd.c_str());
    return 0;
}
