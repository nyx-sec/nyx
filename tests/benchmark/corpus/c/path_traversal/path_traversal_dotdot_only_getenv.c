#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main() {
    char *path = getenv("FILE_PATH");
    /* Rejects `..` but not absolute paths: FILE_PATH=/etc/shadow still opens. */
    if (strstr(path, "..") != NULL) {
        return 1;
    }
    FILE *fp = fopen(path, "r");
    fclose(fp);
    return 0;
}
