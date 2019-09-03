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

#include <stdarg.h>
#include <stdio.h>
#include "elogger.h"
#include "enclave_t.h"

static bool LOGGING_ENABLED = LOGGING_ENABLED_DEFAULT;
static bool LOGGING_DEBUG_ENABLED = LOGGING_DEBUG_ENABLED_DEFAULT;

/*
 * Sets the debug level of this enclave. Used for the enclave_log and debug_log OCALLs.
*/
void ecall_set_logging(bool logging, bool debug){
    LOGGING_ENABLED = logging;
    LOGGING_DEBUG_ENABLED = debug;
}

/**
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void enclave_log(const char *fmt, ...)
{
    if(LOGGING_ENABLED){
        char buf[BUFSIZ] = {'\0'};
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(buf, BUFSIZ, fmt, ap);
        va_end(ap);
        ocall_log(buf);
    }
}

void debug_log(const char *fmt, ...){
    if(LOGGING_ENABLED & LOGGING_DEBUG_ENABLED){
        char buf[BUFSIZ] = {'\0'};
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(buf, BUFSIZ, fmt, ap);
        va_end(ap);
        ocall_log(buf);
    }
}

void print_public_key(sgx_ec256_public_t* pubkey){
    for (uint32_t i = 0; i < sizeof(sgx_ec256_public_t) ; i++){
        enclave_log("%X", ((uint8_t *) pubkey)[i]);
    }
    enclave_log("\n");
}

void print_private_key(sgx_ec256_private_t* privkey){
    for (uint32_t i = 0; i < sizeof(sgx_ec256_private_t) ; i++){
        enclave_log("%X", ((uint8_t *) privkey)[i]);
    }
    enclave_log("\n");
}
