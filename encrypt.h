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


#if !defined(ENCRYPT_H)
#define ENCRYPT_H

#include "rsa.h"

typedef struct {
  uint64_t len;
  const byte *txt;
} msg_t;


// Structure representing an encrypted message.
// Message encryption is done with an RSA 4096 bit long public key, that is used
// to encrypt
typedef struct {
  uint64_t keylen; // length of the key, usually 512 bytes
  const byte *key; // RSA4096-OAEP encrypted AES256 key, to decode msg
  uint64_t keyhashlen; // length of the encrypted key hash.
  const byte *keyhash; // sha512 AES256-CBC hash of the original key, crypted with the same key.
  msg_t msg; // variable length AES256-CBC crypted message. Its key is the decrypt of key.
  uint64_t msghashlen; // length of the encrypted message hash.
  const byte *msghash; //hash of txt field of the msg above (sha512), encrypted with AES-CBC (same key as above).
} enc_msg_t;


bool decrypt_message(const rsa_priv_t key, const enc_msg_t msg, msg_t *dec);
void encrypt_message(const rsa_pub_t key, const msg_t msg, enc_msg_t *enc);

void enc_msg_deinit(enc_msg_t *msg);
void msg_deinit(msg_t *msg);


#endif // ENCRYPT_H
