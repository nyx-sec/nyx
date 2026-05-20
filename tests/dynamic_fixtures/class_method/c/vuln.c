/* Phase 19 (Track M.1) — class-method vuln fixture for C.
 *
 * C has no class system; the harness calls a free function whose name
 * follows the `<Class>_<method>` convention (`UserService_run`). The
 * function piping `input` straight into `system(3)` is the SINK. */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void UserService_run(const char *input, size_t len) {
    (void)len;
    char buf[512];
    snprintf(buf, sizeof(buf), "echo %s", input ? input : "");
    /* SINK: tainted input → system(3) */
    system(buf);
}
