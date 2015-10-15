#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "encrypt.h"

#ifdef _WIN32
  #include <fcntl.h>
  #include <io.h>
#endif


void prepare_stdio_steams(void) {
#ifdef _WIN32
  _setmode(fileno(stdin), _O_BINARY);
  _setmode(fileno(stdout), _O_BINARY);
#else
  freopen(NULL, "rb", stdin);
  freopen(NULL, "wb", stdout);
#endif
}


#define N 512


byte* read_all_stdin(size_t *rlen) {
  size_t read_tot = 0, size = 2*N;

  intmax_t read;

  byte *ret = malloc(size);

  while((read = fread(ret + read_tot, 1, N, stdin)) > 0) {
    read_tot += read;

    if (read_tot + N > size) {
      size *= 2;
      ret = realloc(ret, size);
    }
  }

  *rlen = read_tot;

  if (!read_tot || read < 0) {
    free(ret);

    return NULL;
  }

  return ret;
}

// reads from stdin a little endian uint64_t value.
bool read_size(uint64_t *l) {
  byte b[sizeof(uint64_t)];
  if (fread(b, 1, sizeof(uint64_t), stdin) != sizeof(uint64_t)) {
    return false;
  }

  *l = 0;

  for (size_t i = 0; i < sizeof(uint64_t); ++i) {
    *l |= b[i] << 8*i;
  }

  return true;
}


bool read_pair(const byte **pb, uint64_t *l) {
  if (!read_size(l)) {
    return false;
  }

  *pb = malloc((size_t) *l);

  if (fread((void*) *pb, 1, (size_t) *l, stdin) < *l) {
    free((void*) *pb);

    return false;
  }

  return true;
}


bool read_encr_msg(enc_msg_t *enc) {

  return    read_pair(&enc->key, &enc->keylen)
         && read_pair(&enc->keyhash, &enc->keyhashlen)
         && read_pair(&enc->msg.txt, &enc->msg.len)
         && read_pair(&enc->msghash, &enc->msghashlen);
}


int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s priv_file\n", argv[0]);

    return EXIT_FAILURE;
  }

  char *priv_name = argv[1];

  rsa_keypair_t kp;

  FILE *priv = fopen(priv_name, "rb");

  if (!priv) {
    fputs("error: cannot open key file for reading\n", stderr);

    return EXIT_FAILURE;
  }

  bool failed = !rsa_read_privkey(&kp.priv, priv);

  fclose(priv);

  if (failed) {
    fputs("error: cannot read key\n", stderr);

    return EXIT_FAILURE;
  }

  enc_msg_t enc;
  msg_t dec;

  prepare_stdio_steams();

  if (!read_encr_msg(&enc)) {
    fputs("error: cannot read input\n", stderr);

    return EXIT_FAILURE;
  }

  if (!decrypt_message(kp.priv, enc, &dec)) {
    fputs("error: corrupted message\n", stderr);

    return EXIT_FAILURE;
  }

  fwrite(dec.txt, 1, dec.len, stdout);

  return EXIT_SUCCESS;
}
