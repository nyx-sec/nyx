#include <stdlib.h>

static void drop(void *p)
{
	free((char *)p);
}

void releases_twice(void)
{
	char *p = malloc(8);

	drop(p);
	free(p);
}
