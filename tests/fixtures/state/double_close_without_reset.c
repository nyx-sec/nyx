#include <fcntl.h>
#include <unistd.h>

/* No reset after the first close: the cleanup closes again.
   Expected: state-double-close. */
int rewrite_twice(const char *path) {
    int in_fd = open(path, O_RDONLY);
    if (in_fd < 0)
        return -1;
    close(in_fd);
    close(in_fd);
    return 0;
}
