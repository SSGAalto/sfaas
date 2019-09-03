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

#ifndef _JS_ENCLAVE_JS_H_
#define _JS_ENCLAVE_JS_H_

#if defined(__cplusplus)
extern "C" {
#endif

#include "datatypes.h"
#include  "enclave_t.h"
#include "duktape.h"

void duktape_error(void *udata, const char *msg);

void register_native_functions(duk_context *ctx);


#if defined(__cplusplus)
}
#endif

#endif
