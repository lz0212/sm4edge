/**
 * @file sm4.h
 * @author liuzhen (lz17521640426@163.com)
 * @brief 
 * @version 0.1
 * @date 2022-05-12
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "n2n.h"

#ifndef SM4_H
# define SM4_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "portable_endian.h"

# ifdef OPENSSL_NO_SM4
#  error SM4 is disabled.
# endif

# define SM4_ENCRYPT     1
# define SM4_DECRYPT     0

# define SM4_BLOCK_SIZE    16
# define SM4_KEY_SCHEDULE  32
#define SM4_IV_SIZE       (SM4_BLOCK_SIZE)

typedef struct sm4_context_t {
    uint32_t rk[SM4_KEY_SCHEDULE];
} sm4_context_t;

/**
 * @brief 新增sm4
 * 
 */

int sm4_cbc_encrypt (unsigned char *out, const unsigned char *in, size_t in_len,
                    const unsigned char *iv, sm4_context_t *ctx);

int sm4_cbc_decrypt (unsigned char *out, const unsigned char *in, size_t in_len,
                    const unsigned char *iv, sm4_context_t *ctx);

int sm4_ecb_decrypt (unsigned char *out, const unsigned char *in, sm4_context_t *ctx);

int sm4_init (const unsigned char *key, sm4_context_t **ctx);

int sm4_deinit (sm4_context_t *ctx);


#endif //SM4_H