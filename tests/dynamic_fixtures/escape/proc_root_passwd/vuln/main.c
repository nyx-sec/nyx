/*
 * Phase 20 (Track E.5) — escape fixture: open `/proc/1/root/etc/passwd`.
 *
 * The `/proc/<pid>/root` symlink resolves to the rootfs view of the named
 * process — for PID 1 in the host namespace, that is the host rootfs even
 * after the calling process chroot'd.  Under Phase 17 hardening,
 * `unshare(CLONE_NEWPID|CLONE_NEWUSER)` swaps in a private PID namespace
 * where the harness is itself PID 1, so `/proc/1/root` resolves to the
 * harness's chroot view rather than the host rootfs.  Combined with
 * `chroot(workdir)`, the `/etc/passwd` read either fails open or returns
 * the (absent) workdir copy.
 *
 * Sentinel: if the host `/etc/passwd` were reachable, the harness would
 * copy its first 64 bytes to `/tmp/nyx_escape_proc_root_sentinel`.  Under
 * chroot the sentinel write itself fails (workdir/tmp does not exist) or
 * lands inside the sandbox, so the host path stays absent.
 */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SENTINEL_PATH "/tmp/nyx_escape_proc_root_sentinel"

int main(void) {
    printf("__NYX_SINK_HIT__\n");
    fflush(stdout);

    int src = open("/proc/1/root/etc/passwd", O_RDONLY);
    if (src >= 0) {
        char buf[64];
        ssize_t n = read(src, buf, sizeof(buf));
        close(src);
        if (n > 0) {
            int dst = open(SENTINEL_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (dst >= 0) {
                ssize_t _ignored = write(dst, buf, (size_t)n);
                (void)_ignored;
                close(dst);
                printf("escape:proc_root:copied bytes=%zd\n", n);
            } else {
                printf("escape:proc_root:sentinel_write_failed\n");
            }
        } else {
            printf("escape:proc_root:read_returned=%zd\n", n);
        }
    } else {
        printf("escape:proc_root:open_failed\n");
    }

    printf("__NYX_PROBE_DONE__\n");
    return 0;
}
