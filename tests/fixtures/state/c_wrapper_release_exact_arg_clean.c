#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

/* Releases the descriptor on failure and returns the handle to use next. */
static int settle(int fd, int status)
{
	if (status) {
		close(fd);
		fd = -1;
	}
	return fd;
}

/* Frees what `out` points at, not the caller's variable. */
static void reset_buf(char **out)
{
	free(*out);
	*out = malloc(8);
}

int rebinding_wrapper_result(const char *path, int status)
{
	int fd = open(path, O_RDONLY);

	if (fd < 0)
		return 0;
	fd = settle(fd, status);
	if (fd >= 0)
		close(fd);
	return 1;
}

void out_param_is_not_the_variable(void)
{
	char *a = malloc(8);

	reset_buf(&a);
	free(a);
}

void cast_view_is_released_through_either_name(int n, int w)
{
	unsigned char **src = malloc(sizeof(*src) * n);

	if (w) {
		unsigned long **lp = (unsigned long **)src;
		use(lp);
	}
	free(src);
}
