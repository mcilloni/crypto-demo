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
