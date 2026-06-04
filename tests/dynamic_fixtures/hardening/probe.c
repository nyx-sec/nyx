/*
 * Phase 17 (Track E.1) — process-backend hardening probe.
 *
 * Linked statically (no glibc dynamic loader needed) so it runs after
 * `chroot(workdir)` strips access to /usr/lib.  Reads its own
 * `/proc/self` view to determine which Phase 17 primitives applied,
 * then prints a structured `key:value` line per primitive.  The Rust
 * test reads stdout and asserts on each line.
 *
 * The probe is also reused by the path-traversal case: when
 * `argv[1] == "traverse"` it tries to open `/etc/passwd` and reports
 * either `chroot blocked` (open failed) or `chroot escaped` (open
 * succeeded, host file visible).
 *
 * Built at test runtime with `cc -static -O2 -o probe probe.c`.  Test
 * skips with an eprintln! when the host has no `cc` or no static glibc.
 */

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>

static void grep_status(const char *needle, const char *fallback) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) {
        printf("%s%s\n", needle, fallback);
        return;
    }
    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, needle, strlen(needle)) == 0) {
            // Strip trailing newline.
            size_t n = strlen(line);
            if (n && line[n - 1] == '\n') line[n - 1] = '\0';
            printf("%s\n", line);
            found = 1;
            break;
        }
    }
    if (!found) printf("%s%s\n", needle, fallback);
    fclose(f);
}

static void print_rlimit(const char *tag, int resource) {
    struct rlimit rl;
    if (getrlimit(resource, &rl) == 0) {
        printf("%s:%llu/%llu\n", tag,
               (unsigned long long)rl.rlim_cur,
               (unsigned long long)rl.rlim_max);
    } else {
        printf("%s:err\n", tag);
    }
}

static void probe_namespaces(void) {
    // /proc/self/ns/user, /proc/self/ns/pid, /proc/self/ns/mnt are
    // symlinks like `user:[4026531837]`.  We read the link target and
    // print the inode-id portion.
    const char *names[] = {"user", "pid", "mnt"};
    for (int i = 0; i < 3; i++) {
        char path[64];
        char target[256];
        snprintf(path, sizeof(path), "/proc/self/ns/%s", names[i]);
        ssize_t n = readlink(path, target, sizeof(target) - 1);
        if (n > 0) {
            target[n] = '\0';
            printf("ns_%s:%s\n", names[i], target);
        } else {
            printf("ns_%s:err\n", names[i]);
        }
    }
}

static void probe_chroot(void) {
    // After chroot(workdir), `/etc/passwd` should not exist (the harness
    // workdir does not contain /etc).  Open + ENOENT means chroot held.
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0) {
        printf("chroot:blocked errno=%d\n", errno);
    } else {
        char buf[64];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            printf("chroot:escaped read=%zd\n", n);
        } else {
            printf("chroot:escaped read=0\n");
        }
    }
}

int main(int argc, char **argv) {
    // Stream stdout unbuffered.  Output to a pipe is fully buffered by
    // default and flushed only at exit, so any signal that reaps the probe
    // between its last printf and the libc exit-flush loses the *entire*
    // buffer — the run comes back empty even though every line was written.
    // Under the Strict profile on a locked-down CI host that late reap is a
    // transient (best-effort /proc graft, restricted userns), which made the
    // sentinel intermittently vanish.  Unbuffered, each line hits the pipe
    // the instant it is printed and survives a post-completion reap.
    setvbuf(stdout, NULL, _IONBF, 0);

    grep_status("NoNewPrivs:", "\t?");
    grep_status("Seccomp:", "\t?");
    print_rlimit("rlimit_as", RLIMIT_AS);
    print_rlimit("rlimit_cpu", RLIMIT_CPU);
    print_rlimit("rlimit_nofile", RLIMIT_NOFILE);
    probe_namespaces();
    probe_chroot();

    if (argc > 1 && strcmp(argv[1], "traverse") == 0) {
        // Path-traversal acceptance case: a payload that tries to read
        // /etc/passwd outside the workdir.  Exit non-zero so the verifier
        // records NotConfirmed; the probe-level "chroot blocked" line
        // already printed above is what the test asserts on.
        if (open("/etc/passwd", O_RDONLY) >= 0) {
            // chroot did not hold — exit 0 to signal escape (test fails).
            printf("traverse:escaped\n");
            return 0;
        }
        printf("traverse:blocked\n");
        return 7;
    }

    printf("__NYX_PROBE_DONE__\n");
    return 0;
}
