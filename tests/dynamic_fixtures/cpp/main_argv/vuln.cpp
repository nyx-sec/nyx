// Phase 16 — main(argc, argv), vulnerable.
//
// Renamed away from `main` so the harness `main` symbol does not collide.
// Shape marker: int main(int argc, char *argv[])
// Cap: CODE_EXEC.

#include <cstdio>
#include <cstdlib>
#include <string>

int nyx_entry_main(int argc, char *argv[]) {
    std::printf("__NYX_SINK_HIT__\n");
    std::fflush(stdout);
    if (argc < 2) return 0;
    std::string cmd = std::string("echo hello ") + argv[argc - 1];
    std::system(cmd.c_str());
    return 0;
}
