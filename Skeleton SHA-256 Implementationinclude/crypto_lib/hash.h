#ifndef CRYPTO_LIB_HASH_H
#define CRYPTO_LIB_HASH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Compute SHA-256 hash of a message
 * 
 * @param out Output buffer (must be at least 32 bytes)
 * @param in Input message
 * @param inlen Length of input message in bytes
 * @return int 0 on success, non-zero on error
 */
int crypto_hash_sha256(uint8_t out[32], const uint8_t *in, size_t inlen);

/**
 * @brief Initialize SHA-256 context for incremental hashing
 * 
 * Note: This will be implemented in Phase 2
 */
typedef struct sha256_ctx sha256_ctx;
sha256_ctx* sha256_init(void);
int sha256_update(sha256_ctx *ctx, const uint8_t *in, size_t inlen);
int sha256_final(sha256_ctx *ctx, uint8_t out[32]);
void sha256_free(sha256_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif // CRYPTO_LIB_HASH_H