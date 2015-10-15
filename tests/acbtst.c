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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aescbc.h"


void bytes_n_dump(const char *descr, const byte *msg, const size_t len) {
  printf("%s:\n", descr);
  puts("{");
  for (size_t i = 0; i < len; ++i) {
    if (i) {
      fputs(", ", stdout);
    }

    if (i && !(i % 4)) {
      putchar('\n');
    }

    printf("0x%02X", msg[i]);
  }

  puts("\n}");

  putchar('\n');
  putchar('\n');
}


int main(void) {
  aes_key_t key = {{
    0x80, 0x9C, 0x86, 0x46,
    0x4A, 0x2D, 0x39, 0x52,
    0x5B, 0x91, 0x12, 0x31,
    0x9D, 0x96, 0xAB, 0x35,
    0x93, 0x3C, 0x96, 0x5F,
    0xB3, 0xB3, 0xD5, 0x84,
    0xAB, 0x77, 0x0E, 0xFB,
    0x0E, 0xEE, 0x00, 0xA7
  }};

  byte msg[] = {
    0x79, 0x47, 0xD7, 0x8D,
    0xA3, 0x86, 0xAA, 0x65, 
    0x4F, 0x8B, 0x37, 0x02,
    0xE6, 0x13, 0xE8, 0xCE,
    0x72, 0x83, 0xF9, 0xCE,
    0xEA, 0x3D, 0x6B, 0x7D,
    0xD0, 0xB9, 0x0B, 0x90,
    0x7E, 0x83, 0x4C, 0x15,
    0x1D, 0x5C, 0x43, 0x5B,
    0x4C, 0x04, 0xB1, 0x35,
    0xD3, 0x1A, 0x60, 0x79,
    0xC0, 0x92, 0x83, 0xA0,
    0x47, 0xC8, 0x3B, 0x83,
    0x70, 0xB9, 0x92, 0x35,
    0xE4, 0xA6, 0xF1, 0xDA,
    0x52, 0x8B, 0x11, 0x98
  };

  rijndael_key_t keys[15];

  bytes_n_dump("Key", key.bytes, AES_KEY);

  bytes_n_dump("Msg", msg, sizeof msg);

  size_t rs = 0;
  byte* enc = aes_cbc_crypt(&key, msg, sizeof msg, &rs);

  printf("size = %zu\n\n", rs);

  bytes_n_dump("Enc_msg", enc, rs);

  byte *dec = aes_cbc_decrypt(&key, enc, rs, &rs);

  if (!dec) {
    fputs("error: can't decrypt message\n", stderr);

    return EXIT_FAILURE;
  }

  printf("size = %zu\n\n", rs);

  bytes_n_dump("Dec_msg", dec, rs);

  free(enc);
  free(dec);

  return 0;
}
