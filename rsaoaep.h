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
