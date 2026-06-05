// Phase 16 — main(argc, argv), benign.
// Shape marker: int main(int argc, char *argv[])

#include <cstdio>
#include <cstdlib>

int nyx_entry_main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    std::printf("__NYX_SINK_HIT__\n");
    std::fflush(stdout);
    std::system("echo hello");
    return 0;
}
