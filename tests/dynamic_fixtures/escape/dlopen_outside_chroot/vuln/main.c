/*
 * Phase 20 (Track E.5) — escape fixture: dlopen a host library outside the
 * chroot.
 *
 * Statically linked, so the harness itself does not need a dynamic loader
 * to start.  After printing the sink marker the harness uses an inline
 * `dlopen(3)` call against a stable host library path
 * (`/lib/x86_64-linux-gnu/libc.so.6` on Debian/Ubuntu; the test passes
 * regardless of distro because under chroot every absolute path outside
 * the workdir fails open).
 *
 * On success (chroot missing) the harness writes a sentinel file to
 * `/tmp/nyx_escape_dlopen_sentinel` so the test can assert host-side
 * absence.  The dlopen syscall path is best-effort — if the platform
 * statics out `dlopen` (musl-static), the open(2) sentinel still gates
 * the test result.
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SENTINEL_PATH "/tmp/nyx_escape_dlopen_sentinel"

/*
 * Forward-declare dlopen + dlsym so the test does not need libdl at link
 * time on every host.  Static-glibc builds satisfy the symbol; static-musl
 * builds resolve at runtime via a weak reference.  When the symbol is
 * absent the call is skipped — the open(2) sentinel still does the work.
 */
__attribute__((weak)) void *dlopen(const char *, int);
__attribute__((weak)) int   dlclose(void *);

#ifndef RTLD_NOW
#define RTLD_NOW 0x00002
#endif

int main(void) {
    printf("__NYX_SINK_HIT__\n");
    fflush(stdout);

    /*
     * Try a couple of plausible host library locations.  Under chroot the
     * absolute paths resolve to <workdir>/lib/... etc. and dlopen fails
     * with ENOENT.  Outside chroot they succeed on a stock Linux host.
     */
    const char *candidates[] = {
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
        "/usr/lib/libc.so.6",
        NULL,
    };

    int loaded = 0;
    if (dlopen != 0) {
        for (int i = 0; candidates[i]; i++) {
            void *h = dlopen(candidates[i], RTLD_NOW);
            if (h != 0) {
                printf("escape:dlopen:loaded path=%s\n", candidates[i]);
                if (dlclose != 0) (void)dlclose(h);
                loaded = 1;
                break;
            }
        }
    }
    if (!loaded) printf("escape:dlopen:no_path_loaded\n");

    /*
     * Independent of dlopen's outcome, drop a sentinel on a host-absolute
     * path so the test can assert containment.  Under chroot the write
     * lands inside <workdir>/tmp/... and never touches the host /tmp.
     */
    int fd = open(SENTINEL_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        ssize_t _ignored = write(fd, "NYX_ESCAPE_SUCCESS\n", 19);
        (void)_ignored;
        close(fd);
        printf("escape:dlopen:sentinel_written\n");
    } else {
        printf("escape:dlopen:sentinel_failed\n");
    }

    printf("__NYX_PROBE_DONE__\n");
    return 0;
}
