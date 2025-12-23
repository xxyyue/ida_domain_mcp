#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef int (*secure_validate_fn)(const uint8_t*, size_t);
typedef const char* (*secure_part2_fn)(void);

static inline uint8_t rol8(uint8_t x, unsigned r) {
    r &= 7U;
    return (uint8_t)((x << r) | (x >> (8U - r)));
}

// Reversible transform: (1) xor (2) rotate-left (3) add constant depending on index
static void transform(uint8_t b[32]) {
    for (int i = 0; i < 32; i++) {
        b[i] ^= 0x5A;
        b[i] = rol8(b[i], (unsigned)(i & 7));
        b[i] = (uint8_t)(b[i] + (uint8_t)(i * 17));
    }
}

// main stores flag part1 in a mildly obfuscated way too.
static const uint8_t kPart1XorKey = 0x3C;
static const uint8_t kPart1Enc[] = {
    // Encoded bytes for "FLAG{dual_"
    0x7A, 0x70, 0x7D, 0x7B, 0x47,
    0x58, 0x49, 0x5D, 0x50, 0x63
};


static void get_part1(char out[32]) {
    size_t n = sizeof(kPart1Enc);
    for (size_t i = 0; i < n; i++) out[i] = (char)(kPart1Enc[i] ^ kPart1XorKey);
    out[n] = '\0';
}

int main(void) {
    uint8_t in[32];
    ssize_t got = 0;
    while (got < 32) {
        ssize_t r = read(STDIN_FILENO, in + got, 32 - got);
        if (r <= 0) break;
        got += r;
    }
    if (got != 32) {
        puts("Need exactly 32 bytes input.");
        return 1;
    }

    transform(in);

    void *h = dlopen("./secure_check.so", RTLD_NOW);
    if (!h) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 2;
    }

    secure_validate_fn validate = (secure_validate_fn)dlsym(h, "secure_validate");
    secure_part2_fn part2 = (secure_part2_fn)dlsym(h, "secure_part2");
    if (!validate || !part2) {
        fprintf(stderr, "dlsym failed: %s\n", dlerror());
        dlclose(h);
        return 3;
    }

    if (validate(in, 32)) {
        char part1[32];
        get_part1(part1);
        printf("%s%s\n", part1, part2());
        dlclose(h);
        return 0;
    } else {
        puts("Invalid license");
        dlclose(h);
        return 4;
    }
}
