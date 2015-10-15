#ifndef RSA_H
#define RSA_H

#include <stdbool.h>
#include <stdio.h>

#include <openssl/bn.h>

#include "aes.h"

#ifdef __cplusplus
extern "C" {
#endif


#define RSA_KEY 512 //bytes
#define OAEP_K 16 //bytes, k0 == k1
#define OAEP_LEN (RSA_KEY - 1)

#define RSA_EXP 0x10001UL

typedef struct {
  BIGNUM *n;
} rsa_pub_t;


typedef struct {
  BIGNUM *p, *q, *dp, *dq, *q_inv;
} rsa_priv_t;


typedef struct {
  rsa_pub_t pub;
  rsa_priv_t priv;
} rsa_keypair_t;

void rsa_priv_deinit(rsa_priv_t *priv);
void rsa_pub_deinit(rsa_pub_t *pub);

void rsa_keypair_deinit(rsa_keypair_t* kp);
bool rsa_keypair_init(rsa_keypair_t* kp);

bool rsa_read_privkey(rsa_priv_t *key, FILE *f);
bool rsa_read_pubkey(rsa_pub_t *key, FILE *f);

bool rsa_write_privkey(rsa_priv_t key, FILE *f);
bool rsa_write_pubkey(rsa_pub_t key, FILE *f);

byte* rsa_decrypt_block(rsa_priv_t key, const byte *block, size_t len, size_t *rlen);
byte* rsa_encrypt_block(rsa_pub_t key, const byte *block, size_t len, size_t *rlen);

byte* oaep_decode(const byte msg[static OAEP_LEN], size_t *len);
byte* oaep_encode(const byte *msg, size_t len);

void sha512_hash(byte hash[static 64], const byte *msg, size_t len);

#ifdef __cplusplus
}
#endif

#endif // RSA_H
