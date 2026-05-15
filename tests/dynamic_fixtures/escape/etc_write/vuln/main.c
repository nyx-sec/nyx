/*
 * Phase 20 (Track E.5) — escape fixture: write under /etc.
 *
 * Attempts to write `NYX_ESCAPE_SUCCESS` to `/etc/nyx_escape_etc_write_sentinel`.
 * Under `chroot(workdir)` the absolute path resolves to `<workdir>/etc/...`
 * which does not exist, so the open fails with ENOENT — the host's `/etc`
 * is untouched.
 *
 * The test asserts that:
 *   (a) `__NYX_SINK_HIT__` appeared in stdout (else: Track-B regression);
 *   (b) `/etc/nyx_escape_etc_write_sentinel` is absent on the host.
 */

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#define SENTINEL_PATH "/etc/nyx_escape_etc_write_sentinel"

int main(void) {
    printf("__NYX_SINK_HIT__\n");
    fflush(stdout);

    int fd = open(SENTINEL_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        const char *payload = "NYX_ESCAPE_SUCCESS\n";
        ssize_t _ignored = write(fd, payload, 19);
        (void)_ignored;
        close(fd);
        printf("escape:etc_write:open_succeeded\n");
    } else {
        printf("escape:etc_write:open_failed\n");
    }

    printf("__NYX_PROBE_DONE__\n");
    return 0;
}
