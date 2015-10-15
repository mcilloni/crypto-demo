#include <string.h>

#include <openssl/bn.h>

#include "aes.h"
#include "aescbc.h"


void xor_rij(byte *r, const byte *a, const byte *b) {
  for (byte i = 0; i < RIJ_KEY; ++i) {
    r[i] = a[i] ^ b[i];
  }
}


void calculate_iv(byte iv[static RIJ_KEY]) {
  BIGNUM *ivn = BN_new();

  BN_rand(ivn, RIJ_KEY * 8, -1, 0);

  BN_bn2bin(ivn, iv);

  BN_clear_free(ivn);
}


void cbc_pad(byte r[static RIJ_KEY], const byte *msg, size_t remains) {
  char p = RIJ_KEY - remains;

  memcpy(r, msg, remains);

  memset(r + remains, p, p);
}


byte* aes_cbc_crypt(const aes_key_t *key, const byte *msg, const size_t len, size_t *ret_size) {
  size_t en_len = len + RIJ_KEY; // IV is RIJ_KEY length

  // add padding bytes: RIJ_KEY minus last block extra data
  en_len += RIJ_KEY - len % RIJ_KEY;

  *ret_size = en_len;

  byte *ret = malloc(en_len);

  calculate_iv(ret);

  size_t pos = RIJ_KEY;
  size_t remains = len;
  rijndael_key_t keys[15];

  aes_expand_key(key, keys);

  while (remains >= RIJ_KEY) {
    memcpy(ret + pos, msg, RIJ_KEY);

    xor_rij(ret + pos, ret + pos, ret + pos - RIJ_KEY);

    aes_encrypt_block(keys, ret + pos);

    remains -= RIJ_KEY;
    pos += RIJ_KEY;
    msg += RIJ_KEY;
  }

  cbc_pad(ret + pos, msg, remains);

  xor_rij(ret + pos, ret + pos, ret + pos - RIJ_KEY);

  aes_encrypt_block(keys, ret + pos);

  return ret;
}


byte* aes_cbc_decrypt(const aes_key_t *key, const byte *msg, const size_t len, size_t *msg_size) {
  // if len is lesser than 2*RIJ_KEY, or len is not a multiple of RIJ_KEY,
  // than the message is broken, and you should probably feel bad.
  if (len < 2*RIJ_KEY || len % RIJ_KEY) {
    return NULL;
  }

  // because RIJ_KEY bytes are the IV
  byte *decr = malloc(len - RIJ_KEY);

  // the IV is the initial cipher block ("c0")
  msg += RIJ_KEY;

  // calculate rijndael keys for AES block cipher.
  rijndael_key_t keys[15];

  aes_expand_key(key, keys);

  size_t read = 0;

  // Every block is read, decrypted and then XORed with the precedent block.
  for (; read < len - RIJ_KEY; read += RIJ_KEY, msg += RIJ_KEY) {
    memcpy(decr + read, msg, RIJ_KEY);

    aes_decrypt_block(keys, decr + read);

    // let's put the XOR result directly into decr to skip a memcpy.
    xor_rij(decr + read, decr + read, msg - RIJ_KEY);
  }

  // We padded the message with PKCS#5, so every padding byte is equal to the
  // number of bytes of padding.
  // We're now reading the last byte, because it surely is a padding byte.
  byte pad = decr[read - 1];

  // if pad > 16, then it's broken
  if (pad > 16) {
    free(decr);

    return NULL;
  }

  // message size is the number of read bytes, minus the padding ones.
  *msg_size = read - pad;

  // convenience, so strings are already ok.
  decr[*msg_size] = 0;

  return decr;
}
