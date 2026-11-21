#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main() {
    char *path = getenv("FILE_PATH");
    if (strstr(path, "..") != NULL || path[0] == '/') {
        return 1;
    }
    FILE *fp = fopen(path, "r");
    fclose(fp);
    return 0;
}
