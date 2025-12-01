#ifndef SHA2_H
#define SHA2_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declaration for public API
int crypto_hash_sha256(uint8_t out[32], const uint8_t *in, size_t inlen);

#ifdef __cplusplus
}
#endif

#endif // SHA2_H