/* Phase 16 — main(argc, argv), benign.
 *
 * Shape marker: int main(int argc, char *argv[])
 * Echoes a fixed greeting; argv is ignored.
 */
#include <stdio.h>
#include <stdlib.h>

int nyx_entry_main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    printf("__NYX_SINK_HIT__\n");
    fflush(stdout);
    system("echo hello");
    return 0;
}
