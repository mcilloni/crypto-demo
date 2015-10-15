#include <stdlib.h>
#include <string.h>

#include "rsa.h"
#include "rsaoaep.h"


byte* rsa_oaep_decrypt(const rsa_priv_t key, const byte *msg, size_t len, size_t *rlen) {

  // rsa_dcr should be OAEP_LEN long if this is really OAEP
  byte *rsa_dcr = rsa_decrypt_block(key, msg, len, NULL);

  byte *oaep_dcr = oaep_decode(rsa_dcr, rlen);

  free(rsa_dcr);

  return oaep_dcr;
}


byte* rsa_oaep_crypt(const rsa_pub_t key, const byte *msg, size_t len, size_t *rlen) {
  byte *oaep_enc = oaep_encode(msg, len);

  if (!oaep_enc) {
    return NULL;
  }

  byte *ret = rsa_encrypt_block(key, oaep_enc, OAEP_LEN, rlen);

  free(oaep_enc);

  return ret;
}
