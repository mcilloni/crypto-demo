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

#include "rsa.h"

void bytes_n_dump(const byte *msg, const size_t len) {
  for (size_t i = 0; i < len; ++i) {
    if (i && !(i % 16)) {
      putchar('\n');
    }

    printf("%02x ", msg[i]);
  }

  putchar('\n');
}

int main(void) {
  const byte msg[] = "discodildo - SFONDAMI IL CUORE!";

  puts((char*) msg);

  printf("len(msg) == %zu\n\n", strlen((char*) msg));

  bytes_n_dump(msg, (sizeof msg) - 1);

  puts("");

  byte *enc = oaep_encode(msg, (sizeof msg) - 1);

  bytes_n_dump(enc, OAEP_LEN);

  puts("");

  size_t len = 0;

  byte *dec = oaep_decode(enc, &len);

  printf("len(dec) == %zu\n\n", len);

  bytes_n_dump(dec, len);

  printf("\n%s\n", (char*) dec);

  return 0;
}
