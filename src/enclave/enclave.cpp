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

#include <stdlib.h>
#include <assert.h>

#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <string.h>

#include <sgx_tae_service.h>
#include <sgx_trts.h>

#include <immintrin.h>
#include <sgx_thread.h>

#include "duktape.h"
// #include "json.hpp"
// #include "sgx_base_64.hpp"
#include "arch.h"

#include "enclave.h"
#include "elogger.h"
#include "resources.h"

#include "enclave_t.h"

#include "sgx_quote.h"

#include "nrt_tke.h"

// persistent data
key_data_t DATA_BUFFER;

// local var to hold the pointer to sealed data
sgx_sealed_data_t *SEALED_DATA;
uint32_t SEALED_DATA_SIZE;

// ECC context
sgx_ecc_state_handle_t ECC_HANDLE = NULL;

// global vars for status keeping
bool IS_INITIALIZED = false;

// TSX related
__attribute__((aligned(4096))) bool g_processing = false;
sgx_thread_mutex_t g_mutex = SGX_THREAD_MUTEX_INITIALIZER;
sgx_thread_cond_t g_cond = SGX_THREAD_COND_INITIALIZER;
int process_invoked = 0, counter_invoked = 0;
volatile int tsx_failed = 0, tsx_failed_explicit = 0, tsx_failed_conflict = 0, tsx_failed_retry = 0;
volatile int tsx_counter = 0;
volatile int custom_handler_called = 0;
uint8_t ssa_marker[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
extern uint64_t g_original_ssa_rip;
extern uint64_t g_worker_ssa_gpr;
extern uint64_t g_original_rax;

void* ecall_tsx_get_addr( void )
{
    return &g_processing;
}

typedef uint64_t sys_word_t;

struct thread_data_type
{
    sys_word_t  self_addr;
    sys_word_t  last_sp;            /* set by urts, relative to TCS */
    sys_word_t  stack_base_addr;    /* set by urts, relative to TCS */
    sys_word_t  stack_limit_addr;   /* set by urts, relative to TCS */
    sys_word_t  first_ssa_gpr;      /* set by urts, relative to TCS */
    sys_word_t  stack_guard;        /* GCC expects start_guard at 0x14 on x86 and 0x28 on x64 */

    sys_word_t  flags;
    sys_word_t  xsave_size;         /* in bytes (se_ptrace.c needs to know its offset).*/
    sys_word_t  last_error;         /* init to be 0. Used by trts. */
};

extern "C" void custom_eresume_handler();

void set_ssa_marker()
{
    // void* worker_ssa_gpr = (void*)g_worker_ssa_gpr;
    // memcpy(worker_ssa_gpr, ssa_marker, sizeof(ssa_marker));

    *((uint64_t*)g_worker_ssa_gpr) = 12345;
}

int check_ssa_marker()
{
    // void* worker_ssa_gpr = (void*)g_worker_ssa_gpr;
    // return memcmp(worker_ssa_gpr, ssa_marker, sizeof(ssa_marker));

    return (*((uint64_t*)g_worker_ssa_gpr) == 12345);
}

int ecall_set_worker_ssa( void** p_thread, uint64_t* cssa )
{
    ssa_gpr_t *worker_ssa_gpr;
    struct thread_data_type* thread_data = (struct thread_data_type*)sgx_thread_self();
    // worker_ssa = *((uint64_t*)(&tcs[16]));
    *p_thread = (void*)sgx_thread_self();
    //memcpy(cssa, (void*)((struct thread_data_type*)(*p_thread))->self_addr, sizeof(uint64_t));
    worker_ssa_gpr = reinterpret_cast<ssa_gpr_t *>(thread_data->first_ssa_gpr);
    g_worker_ssa_gpr = (uint64_t)worker_ssa_gpr;
    set_ssa_marker();

    return SGX_SUCCESS;
}

int ecall_counter( void )
{
    unsigned int status;
    int internal_counter = 0;
    ssa_gpr_t *worker_ssa_gpr;

    sgx_thread_mutex_lock(&g_mutex);

    while( !g_processing ) {
      // This check avoids deadlock if the counter thread
      // started after processing thread is finished
      if( process_invoked > counter_invoked ) {
        counter_invoked++;
        sgx_thread_mutex_unlock(&g_mutex);
        return SGX_SUCCESS;
      }

      sgx_thread_cond_wait(&g_cond, &g_mutex);
    }

    while( g_processing ) {
      tsx_counter = internal_counter;
      while( check_ssa_marker() );
      if(( status = _xbegin()) == _XBEGIN_STARTED) {
        // Cannot do ocall's from within TSX
        // enclave_log(" started successfully.\n");
        if( check_ssa_marker() )
          _xabort(_XABORT_EXPLICIT);
        for(int i = 0; i < SGX_TIMER_TICK_DURATION; i++);
        internal_counter = internal_counter + 1;
        // while(g_processing) {
        // }
        _xend();
      } else {
        tsx_failed++;
        if( status & _XABORT_EXPLICIT )
          tsx_failed_explicit++;
        if( status & _XABORT_CONFLICT )
          tsx_failed_conflict++;
        if( status & _XABORT_RETRY )
          tsx_failed_retry++;
      }

      if( check_ssa_marker() ) {
        worker_ssa_gpr = (ssa_gpr_t*)g_worker_ssa_gpr;
        // g_original_rax = worker_ssa_gpr->REG(ax);
        g_original_ssa_rip = worker_ssa_gpr->REG(ip);
        worker_ssa_gpr->REG(ip) = (uint64_t)&custom_eresume_handler;
      }
    }

    counter_invoked++;
    sgx_thread_mutex_unlock(&g_mutex);

    return SGX_SUCCESS;
}

/**
 * PSE session establishment and destroy 
*/
JS_STATUS ecall_init_session(){
    sgx_status_t ret = sgx_create_pse_session();
    return ret;
}

JS_STATUS ecall_destroy_session(){
    sgx_status_t ret = sgx_close_pse_session();
    return ret;
}

JS_STATUS shutdown_internal(void* ctx){
    enclave_log("[ENCLAVE] [SHUTDOWN] Shutting down...ECC");
    JS_STATUS ret = SGX_ERROR_UNEXPECTED;
    if(ECC_HANDLE){
        ret = sgx_ecc256_close_context(ECC_HANDLE);
        if(ret != SGX_SUCCESS){
            enclave_log("[ENCLAVE] [SHUTDOWN] Error closing ECC context");
        }
    }

    enclave_log("...JS-Engine");
    if(ctx != NULL){
        duk_destroy_heap((duk_context*)ctx);
    }

    // Hack to make sure we can join counter thread
    g_processing = false;
    process_invoked = 1;
    counter_invoked = 0;
    sgx_thread_cond_signal(&g_cond);
    enclave_log("...done\n");
    return ret;
}

JS_STATUS ecall_shutdown(){
    return shutdown_internal(NULL);
}

// Attestation requires key derivation
// shared key is 32 bytes in little endian
// Feed SHA with its hex representation
sgx_status_t key_derivation(const sgx_ec256_dh_shared_t* shared_key,
    uint16_t kdf_id,
    sgx_ec_key_128bit_t* smk_key,
    sgx_ec_key_128bit_t* sk_key,
    sgx_ec_key_128bit_t* mk_key,
    sgx_ec_key_128bit_t* vk_key)
{
    sgx_status_t sgx_ret = SGX_SUCCESS;
    sgx_sha_state_handle_t sha_context;
    sgx_sha256_hash_t key_material;
    const char *hex = "0123456789abcdef";
    uint8_t hash_buffer[2*sizeof(sgx_ec256_dh_shared_t)];

    if( NULL == shared_key )
        return SGX_ERROR_INVALID_PARAMETER;

    for( int i = 0; i < sizeof(sgx_ec256_dh_shared_t); i++ ) {
        hash_buffer[ 2*i ]     = hex[ shared_key->s[i] / 16 ];
        hash_buffer[ 2*i + 1 ] = hex[ shared_key->s[i] % 16 ];
    }
    // memcpy(hash_buffer, shared_key, sizeof(sgx_ec256_dh_shared_t));

    sgx_ret = sgx_sha256_init(&sha_context);
    if( sgx_ret != SGX_SUCCESS )
        return sgx_ret;

    sgx_ret = sgx_sha256_update(hash_buffer, sizeof(hash_buffer), sha_context);
    if( sgx_ret != SGX_SUCCESS ) {
        sgx_sha256_close(sha_context);
        return sgx_ret;
    }

    sgx_ret = sgx_sha256_get_hash(sha_context, &key_material);
    if( sgx_ret != SGX_SUCCESS ) {
        sgx_sha256_close(sha_context);
        return sgx_ret;
    }
    sgx_sha256_close(sha_context);

    memcpy(sk_key, key_material, sizeof(sgx_ec_key_128bit_t));
    memset(key_material, 0, sizeof(sgx_sha256_hash_t));

    return SGX_SUCCESS;
}

/**
 * Init:
 * Initializes the enclave with its global key by reloading a sealed buffer
 * 
*/
JS_STATUS ecall_initialize_reload(void* buffer, uint32_t buffer_size){
    JS_STATUS ret = SGX_ERROR_UNEXPECTED;

    if( !ECC_HANDLE ) {
      // Create ECC context and generate keys into our data buffer
      ret = sgx_ecc256_open_context(&ECC_HANDLE);
      if(ret != SGX_SUCCESS){
        enclave_log("[ENCLAVE] [SETUP] Error opening ECC context\n");
        return ret;
      }
    }
    
    enclave_log("[ENCLAVE] [INIT] Reloading instance...\n");
    // Cast buffer into sealed data struct
    sgx_sealed_data_t* p_sealed_data = (sgx_sealed_data_t *) buffer;
   
    // Make sure our data is empty
    memset_s(&DATA_BUFFER, sizeof(key_data_t), 0, sizeof(key_data_t));
    // Check params
	uint32_t sealed_size = sgx_calc_sealed_data_size(0,sizeof(key_data_t));
	if(sealed_size != buffer_size){
	    enclave_log("[ENCLAVE] [INIT] buffer size and required size do not match: given: %i != %i (required)\n", buffer_size, sealed_size);
		return SGX_ERROR_INVALID_PARAMETER;
	}

	// Do bounds checking on buffer: Is it strictly outside enclave?
	if(!sgx_is_within_enclave(p_sealed_data, buffer_size)){
	    // Buffer is violating enclave boundaries: Abort
	    enclave_log("[ENCLAVE] [INIT] Sealed Buffer is violating enclave boundaries. Aborting\n");
	    return SGX_ERROR_INVALID_PARAMETER;
	}

    // unseal
    ret = sgx_unseal_data(p_sealed_data, NULL, 0, (uint8_t*)&DATA_BUFFER, &sealed_size);
    if(ret == SGX_SUCCESS){
        IS_INITIALIZED = true;
        enclave_log("[ENCLAVE] [INIT] Successfully restored persistent data.\n");
    }else{
        enclave_log("[ENCLAVE] [INIT] ERROR restoring persistent data!\n");
        return ret;
    }

    // Log public keys for debugging
    enclave_log("[ENCLAVE] [INIT] Successfully read keys!\n");
    enclave_log("[ENCLAVE] [INIT] Signing public key:");
    print_public_key(&DATA_BUFFER.signing_public);
    enclave_log("[ENCLAVE] [INIT] DH public key:");
    print_public_key(&DATA_BUFFER.dh_public);

    enclave_log("[ENCLAVE] [INIT] ... reload done\n");


    return ret;    
}

/*
 * Initializes an enclave by provisioning it with a key.
 * Outputs a sealed buffer to be used on the next startup.
*/
JS_STATUS ecall_initialize_provision(nrt_ra_context_t context, void* buffer, uint32_t buffer_size,
                                     void* msg_p, uint32_t msg_size)
{
    JS_STATUS retval = SGX_SUCCESS;
    sgx_aes_gcm_128bit_key_t sk_key;
    uint8_t iv[SGX_AESGCM_IV_SIZE] = {0};
    key_data_t keys;
    sgx_aes_gcm_data_t *enc_msg = (sgx_aes_gcm_data_t*)msg_p;

    enclave_log("[ENCLAVE] [INIT] [PROVISION] Provisioning instance from remote enclave...\n");

    retval = nrt_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
    if( retval != SGX_SUCCESS )
      return retval;

    retval = sgx_rijndael128GCM_decrypt(&sk_key, enc_msg->payload, enc_msg->payload_size,
                                        (uint8_t*)&keys,
                                        iv, SGX_AESGCM_IV_SIZE, NULL, 0,
                                        (sgx_aes_gcm_128bit_tag_t*)enc_msg->payload_tag);
    if( retval != SGX_SUCCESS )
      return retval;

    enclave_log("[ENCLAVE] [INIT] Signing public key:");
    print_public_key(&(keys.signing_public));
    enclave_log("[ENCLAVE] [INIT] DH public key:");
    print_public_key(&(keys.dh_public));

    memcpy(&DATA_BUFFER, &keys, sizeof(key_data_t));

    enclave_log("[ENCLAVE] [INIT] [PROVISION] ...provisioning done\n");

    // Now seal the struct
    uint32_t sealed_size = sgx_calc_sealed_data_size(0, sizeof(key_data_t));
    enclave_log("[ENCLAVE] [INIT] [PROVISION] size of key_data_t %d\n", sizeof(key_data_t));
    enclave_log("[ENCLAVE] [INIT] [PROVISION] size of sgx_ec256_private_t %d\n", sizeof(sgx_ec256_private_t));
    if(buffer_size != sealed_size){
        enclave_log("[ENCLAVE] [INIT] [PROVISION] Buffer size is not equal to expected size (%u != %u (expected)). Aborting.\n", buffer_size, sealed_size);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    retval = sgx_seal_data(0, NULL, sizeof(key_data_t),
            (uint8_t*)(&DATA_BUFFER), buffer_size, (sgx_sealed_data_t *)buffer);

    return retval;
}

/**
 * Calculates the data size needed by the internal library data when storing as sealed blob
 */
uint32_t ecall_get_persistent_buffer_size() {
    return sgx_calc_sealed_data_size(0, sizeof(key_data_t));
}

/*
    Useful duktape functions:
    // returns index of top value. However this can also be done by using -1 as index
    duk_idx_t top_id = duk_get_top_index(ctx);
        
    duk_int_t top_type = duk_get_type(ctx, -1);
    debug_log("stack top type is %i\n", top_type);

    duk_double_t top_number = duk_get_number(ctx, -1);
    debug_log("stack top number is %f\n",  top_number);

    debug_log("stack top number is %s\n",  duk_get_string(ctx, -1));

*/

// Remote Attestation
int ecall_enclave_init_ra( int b_pse, nrt_ra_context_t *p_context )
{
    sgx_status_t ret;
    if( b_pse ) {
        int busy_retry = 2;
        do {
            ret = sgx_create_pse_session();
        } while( ret == SGX_ERROR_BUSY && busy_retry-- );

        if( ret != SGX_SUCCESS )
            return ret;
    }
    ret = nrt_ra_init_ex( b_pse, key_derivation, p_context );
    if( b_pse ) {
        sgx_close_pse_session();
    }
    return ret;
}

int ecall_enclave_close_ra( nrt_ra_context_t context )
{
    sgx_status_t ret;
    ret = nrt_ra_close( context );
    return ret;
}
