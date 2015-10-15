#if !defined(AESCBC_H)
#define AESCBC_H

#if defined(__cplusplus)
extern "C" {
#endif

#include "aes.h"

byte* aes_cbc_crypt(const aes_key_t *key, const byte *msg, const size_t len, size_t *ret_size);
byte* aes_cbc_decrypt(const aes_key_t *key, const byte *msg, const size_t len, size_t *msg_size);

#if defined(__cplusplus)
}
#endif

#endif //AESCBC_H
