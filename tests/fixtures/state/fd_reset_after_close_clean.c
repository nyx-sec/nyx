#include <fcntl.h>
#include <unistd.h>

/* The descriptor is closed and reset to -1, so the cleanup block's
   guarded close does not run again.  Expected: no state findings. */
int rewrite(const char *path, int early) {
    int ret = -1;
    int in_fd = open(path, O_RDONLY);
    if (in_fd < 0)
        goto out;
    if (early)
        goto out;
    close(in_fd);
    in_fd = -1;
    ret = 0;
out:
    if (in_fd >= 0)
        close(in_fd);
    return ret;
}
