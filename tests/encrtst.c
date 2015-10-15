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

#include "encrypt.h"


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

  enc_msg_t enc;
  encrypt_message(kp.pub, (msg_t){.len = sizeof msg, .txt = msg}, &enc);

  msg_t dec;
  if (!decrypt_message(kp.priv, enc, &dec)) {
    fputs("error: corrupted message\n", stderr);

    return EXIT_FAILURE;
  }

  fwrite(dec.txt, 1, dec.len, stdout);

  putchar('\n');

  return EXIT_SUCCESS;
}
