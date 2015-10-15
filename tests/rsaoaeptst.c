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


#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "rsaoaep.h"


void bytes_n_dump(const byte *msg, const size_t len) {
  for (size_t i = 0; i < len; ++i) {
    if (i && !(i % 16)) {
      putchar('\n');
    }

    printf("%02x ", msg[i]);
  }

  putchar('\n');
}


int main(int argc, char *argv[]) {
  if (argc != 3) {
    fprintf(stderr, "usage: %s priv_file pub_file\n", argv[0]);

    return EXIT_FAILURE;
  }

  const byte msg[] = "discodildo - SFONDAMI IL CUORE!";

  char *priv_name = argv[1];
  char *pub_name = argv[2];

  rsa_keypair_t kp;

  FILE *pub = fopen(pub_name, "rb");
  FILE *priv = fopen(priv_name, "rb");

  if (!pub || !priv) {
    fputs("error: cannot open key files for reading\n", stderr);

    return EXIT_FAILURE;
  }

  bool failed = !rsa_read_pubkey(&kp.pub, pub) || !rsa_read_privkey(&kp.priv, priv);

  fclose(pub);
  fclose(priv);

  if (failed) {
    fputs("error: cannot read keys\n", stderr);

    return EXIT_FAILURE;
  }

  puts((char*) msg);

  printf("len(msg) == %zu\n\n", strlen((char*) msg));

  puts("orig:");
  bytes_n_dump(msg, (sizeof msg) - 1);

  puts("");

  size_t len;

  byte *enc = rsa_oaep_crypt(kp.pub, msg, (sizeof msg) - 1, &len);
  bytes_n_dump(enc, len);

  puts("");

  byte *dec = rsa_oaep_decrypt(kp.priv, enc, len, &len);

  puts("orig:");
  bytes_n_dump(dec, len);

  printf("\n%s\n", (char*) dec);

  return 0;
}
