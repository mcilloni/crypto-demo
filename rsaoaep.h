#ifndef RSAOAEP_H
#define RSAOAEP_H

#include "rsa.h"

#ifdef __cplusplus
extern "C" {
#endif

byte* rsa_oaep_crypt(const rsa_pub_t key, const byte *msg, size_t len, size_t *rlen);
byte* rsa_oaep_decrypt(const rsa_priv_t key, const byte *msg, size_t len, size_t *rlen);

#ifdef __cplusplus
}
#endif

#endif // RSAOAEP_H
