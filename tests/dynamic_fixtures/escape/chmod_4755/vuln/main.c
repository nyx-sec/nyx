/*
 * Phase 20 (Track E.5) — escape fixture: chmod setuid bit (04755).
 *
 * The harness:
 *   1. Prints `__NYX_SINK_HIT__` so the test sees the sink was reached.
 *      Without this, the test fails as a Track-B regression rather than
 *      passing vacuously.
 *   2. Attempts to create `<SENTINEL_PATH>` on the host filesystem and
 *      `chmod` it to mode 04755 (setuid root).  Under Phase 17 hardening:
 *        - `chroot(workdir)` redirects the absolute path so the host file
 *          is never touched;
 *        - even if the file were created, `prctl(PR_SET_NO_NEW_PRIVS)`
 *          strips the setuid bit at the next `execve`.
 *
 * The test asserts that:
 *   (a) `__NYX_SINK_HIT__` appeared in stdout (else: Track-B regression);
 *   (b) the host-absolute sentinel path is absent after the run.
 */

#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

/* Stable, well-known absolute path.  Test removes it before/after each run. */
#define SENTINEL_PATH "/tmp/nyx_escape_chmod_4755_sentinel"

int main(void) {
    /* Sink probe — must fire before the escape attempt. */
    printf("__NYX_SINK_HIT__\n");
    fflush(stdout);

    int fd = open(SENTINEL_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        const char *payload = "NYX_ESCAPE_SUCCESS\n";
        ssize_t _ignored = write(fd, payload, 19);
        (void)_ignored;
        close(fd);
        /* Escalate: setuid root bit. */
        if (chmod(SENTINEL_PATH, 04755) == 0) {
            printf("escape:chmod_4755:applied\n");
        } else {
            printf("escape:chmod_4755:chmod_failed\n");
        }
    } else {
        printf("escape:chmod_4755:open_failed\n");
    }

    printf("__NYX_PROBE_DONE__\n");
    return 0;
}
