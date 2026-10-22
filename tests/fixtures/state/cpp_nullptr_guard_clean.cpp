#include <cstdio>

// Expected: no resource findings.
int read_char(const char* p) {
    FILE* fp = fopen(p, "r");
    if (fp == nullptr) return -1;
    int c = fgetc(fp);
    fclose(fp);
    return c;
}
