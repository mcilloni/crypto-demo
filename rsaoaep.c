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
