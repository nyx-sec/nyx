/* Phase 16 — main(argc, argv), vulnerable.
 *
 * Entry: nyx_entry_main(int argc, char *argv[])
 *
 * Renamed away from `main` so the harness `main` symbol does not collide
 * when the entry source is `#include`d. The harness emitter recognises the
 * shape via the `int main(int argc, char *argv[])` substring in the
 * comment header below, then calls `nyx_entry_main` with payload-bearing
 * argv. Cap: CODE_EXEC.
 *
 * Shape marker: int main(int argc, char *argv[])
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int nyx_entry_main(int argc, char *argv[]) {
    printf("__NYX_SINK_HIT__\n");
    fflush(stdout);
    if (argc < 2) return 0;
    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "echo hello %s", argv[argc - 1]);
    system(cmd);
    return 0;
}
