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


bool read_msg(msg_t *msg) {
  return (msg->txt = read_all_stdin(&msg->len));
}


// writes to stdout a byte. Little endian.
void write_size(char *tag, uint64_t z) {
  //fprintf(stderr, "len(%s) == %zu\n", tag, z);

  for (size_t i = 0; i < sizeof(uint64_t); ++i) {
    byte w = z & 0xFF;

    fwrite(&w, 1, 1, stdout);

    // shift z right of 1 byte.
    z >>= 8;
  }
}


void write_pair(char *tag, const byte *b, const uint64_t l) {
  write_size(tag, l);
  fwrite(b, 1, l, stdout);
}


void write_enc_msg(enc_msg_t enc) {
  write_pair("key", enc.key, enc.keylen);
  write_pair("keyhash", enc.keyhash, enc.keyhashlen);
  write_pair("txt", enc.msg.txt, enc.msg.len);
  write_pair("txthash", enc.msghash, enc.msghashlen);
}


int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s pub_file\n", argv[0]);

    return EXIT_FAILURE;
  }

  char *pub_name = argv[1];

  rsa_keypair_t kp;

  FILE *pub = fopen(pub_name, "rb");

  if (!pub) {
    fputs("error: cannot open key files for reading\n", stderr);

    return EXIT_FAILURE;
  }

  bool failed = !rsa_read_pubkey(&kp.pub, pub);

  fclose(pub);

  if (failed) {
    fputs("error: cannot read key\n", stderr);

    return EXIT_FAILURE;
  }

  msg_t msg;
  enc_msg_t enc;

  prepare_stdio_steams();

  if (!read_msg(&msg)) {
    fputs("error: cannot read input\n", stderr);

    return EXIT_FAILURE;
  }

  encrypt_message(kp.pub, msg, &enc);

  write_enc_msg(enc);
  /*
  msg_t dec;
  if (!decrypt_message(kp.priv, enc, &dec)) {
    fputs("error: corrupted message\n", stderr);

    return EXIT_FAILURE;
  }

  fwrite(dec.txt, 1, dec.len, stdout);
  */

  return EXIT_SUCCESS;
}
