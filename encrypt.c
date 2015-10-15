//  Copyright 2015 Marco Cilloni
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.


#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>

#include "aescbc.h"
#include "rsaoaep.h"
#include "encrypt.h"


/*
 * Generate an AES_KEY symmetric key for message signing.
 */
void gen_aes_key(aes_key_t *key) {
  BIGNUM *k = BN_new();
  BN_rand(k, AES_KEY * 8, -1, 0);

  BN_bn2bin(k, key->bytes);

  BN_clear_free(k);
}


void bytes_n_dump(const char *descr, const byte *msg, const size_t len) {
  printf("%s(len=%zu):\n", descr, len);
  puts("{");
  for (size_t i = 0; i < len; ++i) {
    if (i) {
      fputs(", ", stdout);
    }

    if (i && !(i % 16)) {
      putchar('\n');
    }

    printf("0x%02X", msg[i]);
  }

  puts("\n}");

  putchar('\n');
  putchar('\n');
}


bool validate_hash(const byte *txt, const size_t len, const byte hash[static 64]) {
  byte new_hash[64];
  sha512_hash(new_hash, txt, len);

  return !memcmp(hash, new_hash, 64);
}


bool decrypt_message(const rsa_priv_t key, const enc_msg_t enc, msg_t *dec) {
  size_t k_len;

  byte *extr_k = rsa_oaep_decrypt(key, enc.key, enc.keylen, &k_len);

  if (k_len != AES_KEY) {
    free(extr_k);

    return false;
  }

  aes_key_t k;
  memcpy(k.bytes, extr_k, AES_KEY);

  free(extr_k);

  size_t hash_len;

  byte *keyhash = aes_cbc_decrypt(&k, enc.keyhash, enc.keyhashlen, &hash_len);

  if (!keyhash) {
    return false;
  }

  bool ok = validate_hash(k.bytes, AES_KEY, keyhash);
  free(keyhash);

  if (!ok) {
    return false;
  }

  dec->txt = aes_cbc_decrypt(&k, enc.msg.txt, enc.msg.len, &dec->len);
  if (!dec->txt) {
    return false;
  }

  byte *msghash = aes_cbc_decrypt(&k, enc.msghash, enc.msghashlen, &hash_len);

  if (!msghash) {
    free(msghash);

    return NULL;
  }

  ok = validate_hash(dec->txt, dec->len, msghash);
  free(msghash);

  if (!ok) {
    free((void*) dec->txt);
    return false;
  }

  return true;
}


void encrypt_message(const rsa_pub_t key, const msg_t msg, enc_msg_t *enc) {
  aes_key_t k;
  gen_aes_key(&k);

  enc->key = rsa_oaep_crypt(key, k.bytes, AES_KEY, &enc->keylen);

  byte hash[64];
  sha512_hash(hash, k.bytes, AES_KEY);

  enc->keyhash = aes_cbc_crypt(&k, hash, 64, &enc->keyhashlen);

  enc->msg.txt = aes_cbc_crypt(&k, msg.txt, msg.len, &enc->msg.len);

  sha512_hash(hash, msg.txt, msg.len);

  enc->msghash = aes_cbc_crypt(&k, hash, 64, &enc->msghashlen);
}


void enc_msg_deinit(enc_msg_t *msg) {
  if (!msg) {
    return;
  }

  free((void*) msg->key);
  free((void*) msg->keyhash);
  free((void*) msg->msghash);
  msg_deinit(&msg->msg);
}


void msg_deinit(msg_t *msg) {
  if (!msg) {
    return;
  }

  free((void*) msg->txt);
}
