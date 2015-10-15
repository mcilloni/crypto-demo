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
#include <string.h>

#include "aes.h"


void block_128_dump(byte *block) {
  for (byte i = 0; i < 16; i += 4) {
    printf("%2x %2x %2x %2x\n", block[i], block[i+1], block[i+2], block[i+3]);
  }
}


int main(void) {
  aes_key_t key = {{
    0x2f, 0xaf, 0x56, 0x61,
    0x81, 0x62, 0x15, 0x5f,
    0x63, 0xa6, 0x89, 0xe5,
    0x4d, 0x72, 0xa1, 0x85,
    0xae, 0x2c, 0xa2, 0xe,
    0xd0, 0xd2, 0x18, 0xce,
    0x52, 0x28, 0xaa, 0x72,
    0xc7, 0x7d, 0x64, 0x43
  }};

  byte msg[17] = "bananas, pyjamas";

  rijndael_key_t keys[15];

  puts((char*) msg);

  block_128_dump(msg);

  puts("\n");

  aes_expand_key(&key, keys);

  aes_encrypt_block(keys, msg);

  block_128_dump(msg);

  puts("\n");

  aes_expand_key(&key, keys);
  
  aes_decrypt_block(keys, msg);

  block_128_dump(msg);

  puts((char*) msg);

  return 0;
}
