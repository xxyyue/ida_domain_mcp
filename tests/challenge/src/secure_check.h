#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int secure_validate(const uint8_t *buf, size_t len);
const char* secure_part2(void);

#ifdef __cplusplus
}
#endif