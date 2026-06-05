/*
 * Phase 20 (Track E.5) — escape fixture: bind a raw socket.
 *
 * Creating an `AF_INET` `SOCK_RAW` socket requires `CAP_NET_RAW`.  Under
 * Phase 17 hardening, `--cap-drop=ALL` / the unprivileged user namespace
 * means the calling process lacks the capability; the seccomp filter also
 * denies `socket(AF_INET, SOCK_RAW, ...)` because raw sockets are not in
 * the default-deny allowlist.
 *
 * Sentinel: when the raw socket is created the harness drops a flag file
 * at `/tmp/nyx_escape_raw_socket_sentinel`.  When chroot redirects the
 * write into the workdir, the host path stays absent.
 */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#define SENTINEL_PATH "/tmp/nyx_escape_raw_socket_sentinel"

int main(void) {
    printf("__NYX_SINK_HIT__\n");
    fflush(stdout);

    int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (s >= 0) {
        printf("escape:raw_socket:created\n");
        close(s);

        int fd = open(SENTINEL_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            ssize_t _ignored = write(fd, "NYX_ESCAPE_SUCCESS\n", 19);
            (void)_ignored;
            close(fd);
            printf("escape:raw_socket:sentinel_written\n");
        } else {
            printf("escape:raw_socket:sentinel_failed\n");
        }
    } else {
        printf("escape:raw_socket:socket_failed\n");
    }

    printf("__NYX_PROBE_DONE__\n");
    return 0;
}
