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


#if !defined(AES_H)
#define AES_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdint.h>

#include <openssl/bn.h>

typedef uint8_t byte;
typedef uint16_t dbyte;
typedef uint32_t qbyte;

#define AES_KEY (256 / 8) //bytes
#define RIJ_KEY (128 / 8) //bytes

typedef struct {
  byte bytes[RIJ_KEY];
} rijndael_key_t;

typedef struct {
  byte bytes[AES_KEY];
} aes_key_t;

void qbyte_xor(byte dest[static 4], byte a[static 4], byte b[static 4]);

void aes_expand_key(const aes_key_t *key, rijndael_key_t keys[static 15]);
void aes_decrypt_block(rijndael_key_t keys[static 15], byte state[static RIJ_KEY]);
void aes_encrypt_block(rijndael_key_t keys[static 15], byte state[static RIJ_KEY]);

extern byte sbox[256];
extern byte inv_sbox[256];
extern byte rcon[256];
extern byte mul_2[256];
extern byte mul_3[256];
extern byte mul_9[256];
extern byte mul_11[256];
extern byte mul_13[256];
extern byte mul_14[256];

#if defined(__cplusplus)
}
#endif

#endif //AES_H
