/*
 * Phase 20 (Track E.5) — escape fixture: `setuid(0)`.
 *
 * Calls `setuid(0)` to try to drop into the root uid.  Under Phase 17
 * hardening this fails because:
 *   - the seccomp default-deny filter rejects `setuid` (not in the BASE
 *     allowlist), and
 *   - the unprivileged user namespace's uid map only contains the
 *     calling uid (no path to 0 inside the namespace),
 *   - `prctl(PR_SET_NO_NEW_PRIVS)` would block any subsequent
 *     `execve` of a setuid-root binary even if `setuid` succeeded.
 *
 * Sentinel: when `setuid(0)` succeeds the harness writes
 * `NYX_ESCAPE_SUCCESS` to `/tmp/nyx_escape_setuid_zero_sentinel`.  Under
 * chroot the write is redirected into the workdir; the host path stays
 * absent.
 */

#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#define SENTINEL_PATH "/tmp/nyx_escape_setuid_zero_sentinel"

int main(void) {
    printf("__NYX_SINK_HIT__\n");
    fflush(stdout);

    if (setuid(0) == 0) {
        printf("escape:setuid_zero:applied uid=%u\n", (unsigned)getuid());

        int fd = open(SENTINEL_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            ssize_t _ignored = write(fd, "NYX_ESCAPE_SUCCESS\n", 19);
            (void)_ignored;
            close(fd);
            printf("escape:setuid_zero:sentinel_written\n");
        } else {
            printf("escape:setuid_zero:sentinel_failed\n");
        }
    } else {
        printf("escape:setuid_zero:rejected\n");
    }

    printf("__NYX_PROBE_DONE__\n");
    return 0;
}
