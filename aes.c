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


#include <string.h>

#include "aes.h"

void rijndael_rotate(byte t[static 4]) {
  byte tmp = t[0];

  t[0] = t[1];
  t[1] = t[2];
  t[2] = t[3];
  t[3] = tmp;
}


void rijndael_rotate_n(byte t[static 4], byte n) {
  for (byte i = 0; i < n; ++i) {
    rijndael_rotate(t);
  }
}


void rijndael_rev_rotate(byte t[static 4]) {
  byte tmp = t[3];

  t[3] = t[2];
  t[2] = t[1];
  t[1] = t[0];
  t[0] = tmp;
}


void rijndael_rev_rotate_n(byte t[static 4], byte n) {
  for (byte i = 0; i < n; ++i) {
    rijndael_rev_rotate(t);
  }
}

void qbyte_xor(byte dest[static 4], byte a[static 4], byte b[static 4]) {
  // hope for loop unwinding
  for (byte i = 0; i < 4; ++i) {
    dest[i] = a[i] ^ b[i];
  }
}


void qbyte_sbox(byte t[static 4]) {
  t[0] = sbox[t[0]];
  t[1] = sbox[t[1]];
  t[2] = sbox[t[2]];
  t[3] = sbox[t[3]];
}


void qbyte_inv_sbox(byte t[static 4]) {
  t[0] = inv_sbox[t[0]];
  t[1] = inv_sbox[t[1]];
  t[2] = inv_sbox[t[2]];
  t[3] = inv_sbox[t[3]];
}


void key_schedule_core(byte t[static 4], byte i) {
  rijndael_rotate(t);

  qbyte_sbox(t);
  t[0] ^= rcon[i];
}


/*
 * A 32 byte key must be expanded to a 240 byte key (to get 14 128 bit Rijndael keys)
 * The first 32 bytes of expanded key ARE the encryption key.
 */
void aes_expand_key(const aes_key_t *key, rijndael_key_t keys[static 15]) {
  byte exp[256];

  // copy original key to new expanded key
  memcpy(exp, key->bytes, RIJ_KEY);
  memcpy(exp + RIJ_KEY, key->bytes + RIJ_KEY, RIJ_KEY);

  dbyte gen = 32;
  byte rcon = 1;

  byte t[4];

  while (gen < 240) {

    // We do the following to create 4 bytes of expanded key:

    // - We assign the value of the previous four bytes in the expanded key to t;
    memcpy(t, exp + gen - 4, 4);

    // - We perform the key_schedule_core on t, with the rcon iteration value;
    key_schedule_core(t, rcon);

    // - We increment rcon by 1;
    ++rcon;

    // - We xor t with the four-byte block 32 bytes before the new expanded key.
    qbyte_xor(t, t, exp + gen - 32);

    //   This becomes the next 4 bytes in the expanded key.
    memcpy(exp + gen, t, 4);

    gen += 4;

    // We then do the following three times to create
    // the next twelve bytes of expanded key:

    for (byte i = 0; i < 3; ++i) {
      // - We assign the value of the previous 4 bytes in the expanded key to t
      // (but t is already it)

      // - We exclusive-OR t with the four-byte block 32 bytes before the new expanded key.
      qbyte_xor(t, t, exp + gen - 32);

      // This becomes the next 4 bytes in the expanded key.
      memcpy(exp + gen, t, 4);

      gen += 4;
    }

    // Because this is a 256 bit key, we need further steps:

    // - We assign the value of the previous 4 bytes in the expanded key to t
    //   (already done)

    // - We run each of the 4 bytes in t through Rijndael's S-box
    qbyte_sbox(t);

    // - We exclusive-OR t with the four-byte block 32 bytes before the new expanded key.
    qbyte_xor(t, t, exp + gen - 32);

    // This becomes the next 4 bytes in the expanded key.
    memcpy(exp + gen, t, 4);

    gen += 4;

    // Execute these steps 3 times for a 256 bit key:

    for (byte i = 0; i < 3; ++i) {
      // - We assign the value of the previous 4 bytes in the expanded key to t
      // (but t is already it)

      // - We exclusive-OR t with the four-byte block 32 bytes before the new expanded key.
      qbyte_xor(t, t, exp + gen - 32);

      // This becomes the next 4 bytes in the expanded key.
      memcpy(exp + gen, t, 4);

      gen += 4;
    }

  }

  // Put the key into the several subkeys.
  // Rijndael keys are ready.
  memcpy(keys, exp, 240);
}


void aes_add_round_key(rijndael_key_t key, byte state[static RIJ_KEY]) {
  for (byte i = 0; i < RIJ_KEY; ++i) {
    state[i] ^= key.bytes[i];
  }
}


void aes_mix_column_n(byte state[static RIJ_KEY], byte n) {
  byte a[4];

  /*
   * The array 'a' is simply a copy of the input column.
   */
  for (byte i=0; i<4; ++i) {
    a[i] = state[i*4 + n];
  }

  state[n] = mul_2[a[0]] ^ a[3] ^ a[2] ^ mul_3[a[1]]; /* 2 * a0 + a3 + a2 + 3 * a1 */
  state[4 + n] = mul_2[a[1]] ^ a[0] ^ a[3] ^ mul_3[a[2]]; /* 2 * a1 + a0 + a3 + 3 * a2 */
  state[8 + n] = mul_2[a[2]] ^ a[1] ^ a[0] ^ mul_3[a[3]]; /* 2 * a2 + a1 + a0 + 3 * a3 */
  state[12 + n] = mul_2[a[3]] ^ a[2] ^ a[1] ^ mul_3[a[0]]; /* 2 * a3 + a2 + a1 + 3 * a0 */
}


void aes_mix_columns(byte state[static RIJ_KEY]) {
  for (byte i = 0; i < 4; ++i) {
    aes_mix_column_n(state, i);
  }
}


void aes_shift_rows(byte state[static RIJ_KEY]) {
  // don't touch first row,

  // rotate second row by 1 (rotation like above)
  rijndael_rotate(state + 4);

  // rotate third row by 2
  rijndael_rotate_n(state + 8, 2);

  // rotate fourth row by 4
  rijndael_rotate_n(state + 12, 4);
}


void aes_sub_bytes(byte state[static RIJ_KEY]) {
  for (byte i = 0; i < RIJ_KEY; ++i) {
    state[i] = sbox[state[i]];
  }
}


void aes_rijndael_round(rijndael_key_t key, byte state[static RIJ_KEY]) {
  aes_sub_bytes(state);
  aes_shift_rows(state);
  aes_mix_columns(state);
  aes_add_round_key(key, state);
}


void aes_final_round(rijndael_key_t key, byte state[static RIJ_KEY]) {
  aes_sub_bytes(state);
  aes_shift_rows(state);
  aes_add_round_key(key, state);
}


void aes_encrypt_block(rijndael_key_t keys[static 15], byte state[static RIJ_KEY]) {
  aes_add_round_key(keys[0], state);

  for (byte round = 1; round < 14; ++round) {
    aes_rijndael_round(keys[round], state);
  }

  aes_final_round(keys[14], state);
}


void aes_rev_mix_column_n(byte state[static RIJ_KEY], byte n) {
    byte a[4];

    /*
     * The array 'a' is simply a copy of the input column.
     */
    for (byte i=0; i<4; ++i) {
      a[i] = state[i*4 + n];
    }

    state[n] = mul_14[a[0]] ^ mul_11[a[1]] ^ mul_13[a[2]] ^ mul_9[a[3]]; /* 14 * a0 + 11 * a1 + 13 * a2 + 9 * a3 */
    state[4 + n] = mul_9[a[0]] ^ mul_14[a[1]] ^ mul_11[a[2]] ^ mul_13[a[3]]; /* 9 * a0 + 14 * a1 + 11 * a2 + 13 * a3 */
    state[8 + n] = mul_13[a[0]] ^ mul_9[a[1]] ^ mul_14[a[2]] ^ mul_11[a[3]]; /* 13 * a0 + 9 * a1 + 14 * a2 + 11 * a3 */
    state[12 + n] = mul_11[a[0]] ^ mul_13[a[1]] ^ mul_9[a[2]] ^ mul_14[a[3]]; /* 11 * a0 + 13 * a1 + 9 * a2 + 14 * a3 */
}


void aes_rev_mix_columns(byte state[static RIJ_KEY]) {
  for (byte i = 0; i < 4; ++i) {
    aes_rev_mix_column_n(state, i);
  }
}


void aes_rev_shift_rows(byte state[static RIJ_KEY]) {
  // don't touch first row,

  // rotate second row by 1 (rotation like above)
  rijndael_rev_rotate(state + 4);

  // rotate third row by 2
  rijndael_rev_rotate_n(state + 8, 2);

  // rotate fourth row by 4
  rijndael_rev_rotate_n(state + 12, 4);
}


void aes_rev_sub_bytes(byte state[static RIJ_KEY]) {
  for (byte i = 0; i < RIJ_KEY; ++i) {
    state[i] = inv_sbox[state[i]];
  }
}


void aes_rev_rijndael_round(rijndael_key_t key, byte state[static RIJ_KEY]) {
  aes_add_round_key(key, state);
  aes_rev_mix_columns(state);
  aes_rev_shift_rows(state);
  aes_rev_sub_bytes(state);
}


void aes_rev_final_round(rijndael_key_t key, byte state[static RIJ_KEY]) {
  aes_add_round_key(key, state);
  aes_rev_shift_rows(state);
  aes_rev_sub_bytes(state);
}


void aes_decrypt_block(rijndael_key_t keys[static 15], byte state[static RIJ_KEY]) {
  aes_rev_final_round(keys[14], state);

  for (byte round = 1; round < 14; ++round) {
    aes_rev_rijndael_round(keys[14 - round], state);
  }

  aes_add_round_key(keys[0], state);
}
