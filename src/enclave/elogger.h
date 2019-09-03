/* Copyright (c) 2018 Aalto University
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _JS_ENCLAVE_LOGGER_H_
#define _JS_ENCLAVE_LOGGER_H_

#include <sgx_tcrypto.h>

#if defined(__cplusplus)
extern "C" {
#endif
  
// Sets if logging is enabled or disabled
#define LOGGING_ENABLED_DEFAULT false
#define LOGGING_DEBUG_ENABLED_DEFAULT false

void enclave_log(const char *fmt, ...);
void debug_log(const char *fmt, ...);
void print_public_key(sgx_ec256_public_t* pubkey);
void print_private_key(sgx_ec256_private_t* privkey);

#if defined(__cplusplus)
}
#endif

#endif
