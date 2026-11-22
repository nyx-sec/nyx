#include <stdio.h>
#include <stdlib.h>

#define SNPRINTF2(str, len, fmt, a, b) snprintf((str), (len), (fmt), (a), (b))

void build_and_log(void) {
    char msg[256];
    SNPRINTF2(msg, sizeof(msg), "echo %s %s", "x", "y");
    puts(msg);
}
