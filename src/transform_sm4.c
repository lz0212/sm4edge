/**
 * @file transform_sm4.c
 * @author liuzhen (lz17521640426@163.com)
 * @brief 
 * @version 0.1
 * @date 2022-05-10
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "n2n.h"

#define SM4_PREAMBLE_SIZE       (SM4_BLOCK_SIZE)


// cts/cbc mode is being used with random value prepended to plaintext
// instead of iv so, actual iv is aes_null_iv
const uint8_t sm4_null_iv[SM4_IV_SIZE] = { 0 };

typedef struct transop_sm4 {
    sm4_context_t       *ctx;
} transop_sm4_t;


static int transop_deinit_sm4 (n2n_trans_op_t *arg) {

    transop_sm4_t *priv = (transop_sm4_t *)arg->priv;

    if(priv->ctx)
        sm4_deinit(priv->ctx);

    if(priv)
        free(priv);

    return 0;
}


// the sm4 packet format consists of
//
//  - a random SM4_PREAMBLE_SIZE-sized value prepended to plaintext
//    encrypted together with the...
//  - ... payload data
//
//  [VV|DDDDDDDDDDDDDDDDDDDDD]
//  | <---- encrypted ---->  |
//
static int transop_encode_sm4 (n2n_trans_op_t *arg,
                               uint8_t *outbuf,
                               size_t out_len,
                               const uint8_t *inbuf,
                               size_t in_len,
                               const uint8_t *peer_mac) {
    

    transop_sm4_t *priv = (transop_sm4_t *)arg->priv;

    // the assembly buffer is a source for encrypting data
    // the whole contents of assembly are encrypted
    uint8_t assembly[N2N_PKT_BUF_SIZE];
    size_t idx = 0;
    int padded_len;
    uint8_t padding;
    uint8_t buf[SM4_BLOCK_SIZE];

    if(in_len <= N2N_PKT_BUF_SIZE) {
        if((in_len + SM4_PREAMBLE_SIZE + SM4_BLOCK_SIZE) <= out_len) {
            traceEvent(TRACE_DEBUG, "transop_encode_sm4 %lu bytes plaintext", in_len);

            // full block sized random value (128 bit)
            encode_uint64(assembly, &idx, n2n_rand());
            encode_uint64(assembly, &idx, n2n_rand());

            // adjust for maybe differently chosen AES_PREAMBLE_SIZE
            idx = SM4_PREAMBLE_SIZE;

            // the plaintext data
            encode_buf(assembly, &idx, inbuf, in_len);

            // round up to next whole SM4 block size
            padded_len = (((idx - 1) / SM4_BLOCK_SIZE) + 1) * SM4_BLOCK_SIZE;
            padding = (padded_len-idx);

            // pad the following bytes with zero, fixed length (SM4_BLOCK_SIZE) seems to compile
            // to slightly faster code than run-time dependant 'padding'
            memset(assembly + idx, 0, SM4_BLOCK_SIZE);

            sm4_cbc_encrypt(outbuf, assembly, padded_len, sm4_null_iv, priv->ctx);

            if(padding) {
                // exchange last two cipher blocks
                memcpy(buf, outbuf+padded_len - SM4_BLOCK_SIZE, SM4_BLOCK_SIZE);
                memcpy(outbuf + padded_len - SM4_BLOCK_SIZE, outbuf + padded_len - 2 * SM4_BLOCK_SIZE, SM4_BLOCK_SIZE);
                memcpy(outbuf + padded_len - 2 * SM4_BLOCK_SIZE, buf, SM4_BLOCK_SIZE);
            }
        } else
            traceEvent(TRACE_ERROR, "transop_encode_sm4 outbuf too small");
    } else
    traceEvent(TRACE_ERROR, "transop_encode_sm4 inbuf too big to encrypt");

    return idx;
}


// see transop_encode_sm4 for packet format
static int transop_decode_sm4 (n2n_trans_op_t *arg,
                               uint8_t *outbuf,
                               size_t out_len,
                               const uint8_t *inbuf,
                               size_t in_len,
                               const uint8_t *peer_mac) {

    transop_sm4_t *priv = (transop_sm4_t *)arg->priv;
    uint8_t assembly[N2N_PKT_BUF_SIZE];

    uint8_t rest;
    size_t penultimate_block;
    uint8_t buf[SM4_BLOCK_SIZE];
    int len = -1;

     if(((in_len - SM4_PREAMBLE_SIZE) <= N2N_PKT_BUF_SIZE) /* cipher text fits in assembly */
      && (in_len >= SM4_PREAMBLE_SIZE)                     /* has at least random number */
      && (in_len >= SM4_BLOCK_SIZE)) {                     /* minimum size requirement for cipher text stealing */
        
        traceEvent(TRACE_DEBUG, "transop_decode_sm4 %lu bytes ciphertext", in_len);

        rest = in_len % SM4_BLOCK_SIZE;
        if(rest) { /* cipher text stealing */
            penultimate_block = ((in_len / SM4_BLOCK_SIZE) - 1) * SM4_BLOCK_SIZE;

            // everything normal up to penultimate block
            memcpy(assembly, inbuf, penultimate_block);

            // prepare new penultimate block in buf
            sm4_ecb_decrypt(buf, inbuf + penultimate_block, priv->ctx);
            memcpy(buf, inbuf + in_len - rest, rest);

            // former penultimate block becomes new ultimate block
            memcpy(assembly + penultimate_block + SM4_BLOCK_SIZE, inbuf + penultimate_block, SM4_BLOCK_SIZE);

            // write new penultimate block from buf
            memcpy(assembly + penultimate_block, buf, SM4_BLOCK_SIZE);

            // regular cbc decryption of the re-arranged ciphertext
            sm4_cbc_decrypt(assembly, assembly, in_len + SM4_BLOCK_SIZE - rest, sm4_null_iv, priv->ctx);

            // check for expected zero padding and give a warning otherwise
            if(memcmp(assembly + in_len, sm4_null_iv, SM4_BLOCK_SIZE - rest)) {
                traceEvent(TRACE_WARNING, "transop_decode_sm4 payload decryption failed with unexpected cipher text stealing padding");
                return -1;
            }
        } else {
            // regular cbc decryption on multiple block-sized payload
            sm4_cbc_decrypt(assembly, inbuf, in_len, sm4_null_iv, priv->ctx);
        }
        len = in_len - SM4_PREAMBLE_SIZE;
        memcpy(outbuf, assembly + SM4_PREAMBLE_SIZE, len);
    } else
        traceEvent(TRACE_ERROR, "transop_decode_sm4 inbuf wrong size (%ul) to decrypt", in_len);

    return len;
}


static int setup_sm4_key (transop_sm4_t *priv, const uint8_t *password, ssize_t password_len) {

    uint8_t key_mat[SM4_KEY_SCHEDULE];

    // the input key always gets hashed to make a more unpredictable and more complete use of the key space
    pearson_hash_256(key_mat, password, password_len);

    if(sm4_init(key_mat, &(priv->ctx))) {
        traceEvent(TRACE_ERROR, "setup_sm4_key setup unsuccessful");
        return -1;
    }

    traceEvent(TRACE_DEBUG, "setup_sm4_key completed");

    return 0;
}


static void transop_tick_sm4 (n2n_trans_op_t *arg, time_t now) {

    // no tick action
}


// SM4 initialization function
int n2n_transop_sm4_init (const n2n_edge_conf_t *conf, n2n_trans_op_t *ttt) {

    transop_sm4_t *priv;
    const u_char *encrypt_key = (const u_char *)conf->encrypt_key;
    size_t encrypt_key_len = strlen(conf->encrypt_key);

    memset(ttt, 0, sizeof(*ttt));
    ttt->transform_id = N2N_TRANSFORM_ID_SM4;

    ttt->tick         = transop_tick_sm4;
    ttt->deinit       = transop_deinit_sm4;
    ttt->fwd          = transop_encode_sm4;
    ttt->rev          = transop_decode_sm4;

    priv = (transop_sm4_t*)calloc(1, sizeof(transop_sm4_t));
    if(!priv) {
        traceEvent(TRACE_ERROR, "n2n_transop_sm4_init cannot allocate transop_sm4_t memory");
        return -1;
    }
    ttt->priv = priv;

    // setup the cipher and key
    return setup_sm4_key(priv, encrypt_key, encrypt_key_len);
}
