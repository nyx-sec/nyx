#include <stdlib.h>
#include <stdio.h>

#ifdef USE_FEATURE
int feature(const char *path)
{
	FILE *f = fopen(path, "r");
	char *buf = malloc(64);

	if (!buf)
		return -1;
	if (!f)
		return -1;
	fclose(f);
	return 0;
}
#endif
