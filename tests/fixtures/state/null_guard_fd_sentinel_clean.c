#include <fcntl.h>
#include <unistd.h>

/* open(2) / socket(2) return -1 on failure.  The failure branch holds no
   descriptor.  Expected: no resource findings. */

int read_byte(const char *p) {
    char c;
    int fd = open(p, O_RDONLY);
    if (fd < 0) return -1;
    read(fd, &c, 1);
    close(fd);
    return c;
}

int read_byte_eq(const char *p) {
    char c;
    int fd = open(p, O_RDONLY);
    if (fd == -1) {
        return -1;
    }
    read(fd, &c, 1);
    close(fd);
    return c;
}
