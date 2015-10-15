#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/bn.h>

#include "rsa.h"


void rsa_print_kp(rsa_keypair_t kp) {
  char *v = BN_bn2hex(kp.pub.n);
  printf("n = %s\n", v);

  OPENSSL_free(v);

  v = BN_bn2hex(kp.priv.p);
  printf("p = %s\n", v);

  OPENSSL_free(v);

  v = BN_bn2hex(kp.priv.q);
  printf("q = %s\n", v);

  OPENSSL_free(v);

  v = BN_bn2hex(kp.priv.dp);
  printf("dp = %s\n", v);

  OPENSSL_free(v);

  v = BN_bn2hex(kp.priv.dq);
  printf("dq = %s\n", v);

  OPENSSL_free(v);

  v = BN_bn2hex(kp.priv.q_inv);
  printf("q_inv = %s\n", v);

  OPENSSL_free(v);
}


int main(int argc, char *argv[]) {
  if (argc != 3) {
    fprintf(stderr, "usage: %s priv_file pub_file\n", argv[0]);

    return EXIT_FAILURE;
  }

  char *priv_name = argv[1];
  char *pub_name = argv[2];

  rsa_keypair_t kp;

  rsa_keypair_init(&kp);

  FILE *pub = fopen(pub_name, "wb");
  FILE *priv = fopen(priv_name, "wb");

  if (!pub || !priv) {
    fputs("error: cannot open key files for writing\n", stderr);

    return EXIT_FAILURE;
  }

  if (!rsa_write_pubkey(kp.pub, pub) || !rsa_write_privkey(kp.priv, priv)) {
    fputs("error: cannot write keys\n", stderr);

    return EXIT_FAILURE;
  } else {
    rsa_print_kp(kp);
  }

  fclose(pub);
  fclose(priv);


  // pointless
  //rsa_keypair_deinit(&kp);



  return EXIT_SUCCESS;
}
