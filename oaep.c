#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/evp.h>

#include "rsa.h"


void sha512_hash(byte hash[static 64], const byte *msg, size_t len) {
  EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL);

  EVP_DigestUpdate(mdctx, msg, len);

  EVP_DigestFinal_ex(mdctx, hash, NULL);
  EVP_MD_CTX_destroy(mdctx);
}


void oaep_gen_r(byte r[static OAEP_K]) {
  BIGNUM *rn = BN_new();

  BN_rand(rn, OAEP_K, -1, 0);

  BN_bn2bin(rn, r);

  BN_clear_free(rn);
}


void oaep_g(byte buf[static OAEP_LEN]) {
  byte hash[64];

  // hash r
  sha512_hash(hash, buf + (OAEP_LEN - OAEP_K), OAEP_K);

  for (size_t i = 0; i < OAEP_LEN - OAEP_K; ++i) {
    buf[i] ^= hash[i % OAEP_K];
  }
}


void oaep_h(byte buf[static OAEP_LEN]) {
  byte hash[64];

  // hash m0
  sha512_hash(hash, buf, OAEP_LEN - OAEP_K);

  byte *r = buf + (OAEP_LEN - OAEP_K);

  for (size_t i = 0; i < OAEP_K; ++i) {
    r[i] ^= hash[i];
  }
}


byte* oaep_decode(const byte msg[static OAEP_LEN], size_t *len) {
  byte *ret = calloc(OAEP_LEN, 1);
  memcpy(ret, msg, OAEP_LEN);

  // r = H(X) xor Y
  oaep_h(ret);

  // m0 = X xor G(r)
  oaep_g(ret);

  *len = ret[1] << 8 | ret[0];

  memmove(ret, ret + 2, OAEP_LEN - 2);

  return ret;
}


byte* oaep_encode(const byte *msg, size_t len) {
  // Big messages should be splitted.
  // This is boring and I don't want to do it.
  if (len > OAEP_LEN - 2*OAEP_K - 1 - sizeof(dbyte)) { // sizeof(dbyte) == 2
    return NULL;
  }

  // personal twist: first two bytes are a 16 bit message length value.
  // Little endian.

  byte *ret = calloc(OAEP_LEN, 1);

  // copy len to the first two bytes.
  ret[0] = len & 0xFF;
  ret[1] = len >> 8 & 0xFF;

  memcpy(ret + 2, msg, len);

  // fill with 0:
  // - the bytes after the message, to get m of size n - k0 - k1
  // - the bytes after m, until n - k0
  // Already done by calloc

  // generate an r k0 bits wide.
  oaep_gen_r(ret + (OAEP_LEN - OAEP_K));

  // apply G function
  oaep_g(ret);

  // apply H function
  oaep_h(ret);

  return ret;
}
