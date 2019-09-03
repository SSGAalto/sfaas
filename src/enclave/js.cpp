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
#include "js.h"
#include <string>
#include <sgx_tcrypto.h>
#include <sgx_ecp_types.h>
#include <sgx_thread.h>
#include "duktape.h"
#include "json.hpp"
#include "sgx_base_64.hpp"

#include "datatypes.h"
#include "resources.h"
#include "elogger.h"
#include "enclave.h"

#if defined(__cplusplus)
extern "C" {
#endif

// Duktape context
static duk_context *ctx;
static int duk_ids = 0;

static RuntimeMeasurements* runtime_measurements;

bool EVAL_MODE_NO_ENCRYPT = true;

/*
 * Runtime related variables:
 * - a hash over the input script to include in the output to client
 * - a pointer to the output of the script (json string)
*/
static sgx_sha256_hash_t script_hash;
static std::string script_hash_b64;
static std::string client_output;
static json::JSON client_nonce;
static std::string output_udata;

// persistent data
extern key_data_t DATA_BUFFER;

// ECC context
extern sgx_ecc_state_handle_t ECC_HANDLE;

// global vars for status keeping
extern bool IS_INITIALIZED;

// TSX related
__attribute__((aligned(4096))) extern bool g_processing;
extern sgx_thread_mutex_t g_mutex;
extern sgx_thread_cond_t g_cond;
extern int process_invoked, counter_invoked;
extern int tsx_failed, tsx_failed_explicit, tsx_failed_conflict, tsx_failed_retry;
extern int custom_handler_called;
extern volatile int tsx_counter;

sgx_status_t derive_encryption_key(sgx_ec256_private_t *a, sgx_ec256_public_t *gb,
    sgx_ec_key_128bit_t *skey)
{
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  sgx_ec256_dh_shared_t dh_key;

  ret = sgx_ecc256_compute_shared_dhkey(a, gb, &dh_key, ECC_HANDLE);
  if( ret != SGX_SUCCESS ) {
    enclave_log("[ENCLAVE] [JS] [EXECUTE] Computing shared key failed.\n");
    return ret;
  }

  ret = key_derivation(&dh_key, 0, NULL, skey, NULL, NULL);

  return ret;
}

JS_STATUS ecall_script_init(const char* script, size_t script_len){
    enclave_log("[ENCLAVE] [JS] [INIT] Initializing script...\n");

    runtime_measurements = new RuntimeMeasurements();

    // Create duktape heap
    ctx = duk_create_heap(resource_alloc, resource_realloc, resource_free, runtime_measurements, duktape_error);
    if (!ctx) { return SGX_JS_ERROR_CONTEXT_ERROR; }
    enclave_log("[ENCLAVE] [JS] [INIT] Duktape context created\n");

    // Register native C functions for I/O etc
    register_native_functions(ctx);

    // Hash the script to include it later in the output
    sgx_sha256_msg((uint8_t*) script, script_len, &script_hash);
    script_hash_b64 = sgx_base64::sha256_to_base64(&script_hash);

    // load the script into duktape and finish
    debug_log("[ENCLAVE] [JS] [INIT] Compiling script:\n%s\n", script);
    duk_compile_string(ctx, DUK_COMPILE_FUNCTION, script);



    enclave_log("[ENCLAVE] [JS] [INIT] ...JS script successfully read\n");
}

json::JSON decrypt_input(json::JSON input_json, sgx_ec_key_128bit_t *enc_key)
{
    sgx_status_t ret;
    unsigned char decrypted_input[4096];
    std::string encrypted_input;
    uint8_t aes_ctr[16] = {0};
    aes_ctr[15] = 1;

    // First, generate a shared key out of the user's gb and our private key
    sgx_ec256_public_t client_key;
    sgx_base64::ecc_pk_from_base64(input_json["gb"], &client_key);
    json::JSON key_json = input_json["gb"];

    // Decrypt the input
    ret = derive_encryption_key(&DATA_BUFFER.dh_private, &client_key, enc_key);
    if( ret != SGX_SUCCESS ) {
      enclave_log("[ENCLAVE] [JS] [EXECUTE] Failed to derive input decryption key.\n");
      return input_json;
    }
    encrypted_input = sgx_base64::base64_decode(input_json["input"].ToString());
    ret = sgx_aes_ctr_decrypt(enc_key, (const uint8_t*)encrypted_input.c_str(),
        encrypted_input.length() + 1,  // str length plus \0 at the end
        aes_ctr, 
        128, 
        decrypted_input);

    return json::JSON::Load(std::string((const char*)decrypted_input));
}


/**
 * Run JS
 * Input contains: 
 * {
 * user_dh:<user dh as base64>
 * input:<encrypted_input>
 * }
 * encrypted_input is:
 * {
 * input:<input json>
 * script_hash:<sha256 of script. Abort if different to script>
 * }
 *  - pubkey of user
 *  - script of user (or name)
 *  - input to script
 * 
 * Output:
 *  - Size of encrypted output that is intended for the client
 * 
 * The output to the client contains:
 * {
 *  output:<json>,
 *  receipt:<ecc signature json>
 * }
*/
JS_STATUS ecall_script_run(const char* input, size_t* output_size, size_t* measurement_size){
    json::JSON input_json;
    json::JSON output_json = json::JSON();
    std::string input_json_str;
    const char* input_json_chr;

    sgx_ec_key_128bit_t enc_key = {0};
    uint8_t aes_ctr[16] = {0};
    aes_ctr[15] = 1;


    // ocall_http_io(NULL, NULL, NULL, 0);
    // enclave_log("[ENCLAVE] [JS] [EXECUTE] Running script\n");

    //first, activate resource measurements
    sgx_thread_mutex_lock(&g_mutex);
    set_ssa_marker();
    g_processing = true;
    process_invoked++;
    sgx_thread_cond_signal(&g_cond);
    start_resource_measurements(runtime_measurements);
    sgx_thread_mutex_unlock(&g_mutex);

    
    //enclave_log("[ENCLAVE] [JS] [EXECUTE] Run called with json:\n%s\n", input_json_chr);

    input_json = json::JSON::Load(input);
    if(!EVAL_MODE_NO_ENCRYPT){ // Normal operation -> Decrypt input
        input_json = decrypt_input(input_json, &enc_key);
    }

    // Check requested script hash with our script hash
    // TODO: Activate this in a real world scenario
    /*
    sgx_sha256_hash_t expected_hash = sgx_base64::sha256_from_base64(input_json["script_hash"]);
    int correct = memcmp(&script_hash, &expected_hash, sizeof(sgx_sha256_hash_t));
    if(!correct){
        enclave_log("[ENCLAVE] [RUN] [ERROR] Mismatch of script hashes\n");
        return SGX_JS_ERROR_SCRIPT_HASH_MISMATCH;
    }
    */

    // Read out client nonce
    client_nonce = input_json["nonce"];
    //enclave_log("[ENCLAVE] [JS] [EXECUTE] Client nonce is %s\n", client_nonce.dump().c_str());

    // push the input
    duk_push_string(ctx, input_json["input"].dump().c_str());

    //enclave_log("[ENCLAVE] [JS] [EXECUTE] Plaintext input is:\n%s\n", input_json.dump().c_str()); 
    duk_json_decode(ctx, -1);

    // execute function
    duk_call(ctx, 1);

    // retrieve output
    const char* script_output = duk_get_string(ctx, -1);
    //enclave_log("[ENCLAVE] [JS] [EXECUTE] Script finished execution.\n");
    
    /*
     * Now we have a JSON that contains an output and a measurement_udata element.
     * Convert it to JSON. The output object goes into the output JSON
     *  while the measurement_udata goes into the resource measurements.
     * Take it and wrap it in another JSON that also includes the script hash:
     * {
     * output_encrypted:{nonce:<nonce>,script_hash:<hash generated during init function>, output:<client_output>},
     * receipt:{<ecc signature as json with x and y members>}
     * }
    */
    json::JSON result_json = json::JSON::Load(std::string(script_output));

    // Store the user data of the output to append it to resource measurements later
    if(result_json.hasKey("measurements_udata")){
        output_udata = result_json["measurements_udata"].dump();
    }

    // Create output to client
    json::JSON plaintext_output = json::JSON();
    plaintext_output["nonce"] = client_nonce;
    plaintext_output["script_hash"] = script_hash_b64;
    plaintext_output["output"] = result_json["output"];

    //enclave_log("[ENCLAVE] [JS] [EXECUTE] Plain output of script to client would be:\n%s\n", output_str.c_str()); 
   
    /**
     * If signing is requested, sign the output
     * For this, we create a receipt by combining hashes of
     *  - Input to script
     *  - Script
     *  - Output of script
    */
    sgx_status_t sgx_ret;
   if(false){
        sgx_sha256_hash_t receipt_hash;
        sgx_sha_state_handle_t sha_context;
        sgx_ret = sgx_sha256_init(&sha_context);
        if( sgx_ret != SGX_SUCCESS )
            return sgx_ret;

        // Input
        input_json_str = input_json["input"].dump();
        size_t input_length = input_json_str.length() + 1;
        sgx_ret = sgx_sha256_update((const uint8_t*) input_json_str.c_str(), input_length, sha_context);
        if( sgx_ret != SGX_SUCCESS ) {
            sgx_sha256_close(sha_context);
            return sgx_ret;
        }

        // Script
        sgx_ret = sgx_sha256_update((const uint8_t*) script_hash, sizeof(sgx_sha256_hash_t), sha_context);
        if( sgx_ret != SGX_SUCCESS ) {
            sgx_sha256_close(sha_context);
            return sgx_ret;
        }

        // Output
        std::string output_str = result_json["output"].dump();
        sgx_ret = sgx_sha256_update((const uint8_t*) output_str.c_str(), output_str.length() + 1, sha_context);
        if( sgx_ret != SGX_SUCCESS ) {
            sgx_sha256_close(sha_context);
            return sgx_ret;
        }

        // Get hash and close context
        sgx_ret = sgx_sha256_get_hash(sha_context, &receipt_hash);
        if( sgx_ret != SGX_SUCCESS ) {
            sgx_sha256_close(sha_context);
            return sgx_ret;
        }
        sgx_sha256_close(sha_context);
    
        sgx_ec256_signature_t output_signature;
            sgx_ret = sgx_ecdsa_sign(
                (uint8_t*) receipt_hash, 
                sizeof(sgx_sha256_hash_t), // str length plus \0 at the end
                &DATA_BUFFER.signing_private, 
                &output_signature, 
                ECC_HANDLE);
            if (sgx_ret != SGX_SUCCESS) {
                //enclave_log("[ENCLAVE] [JS] [EXECUTE] Failed to sign output.\n");
                return sgx_ret;
            } else {
                //enclave_log("[ENCLAVE] [JS] [EXECUTE] Output signature generated.\n");
            }
        
        output_json["receipt"] = sgx_base64::signature_to_base64(&output_signature);
   }

    // Now wrap this in another json with the signature and the encrypted data
    if(EVAL_MODE_NO_ENCRYPT){
        output_json["output_encrypted"] = plaintext_output;
    } else {
        std::string output_str = plaintext_output.dump();
        // encrypt plaintext output to base64
        size_t output_len = output_str.length() + 1;
        void* encrypted_bytes = malloc(output_len);
        sgx_ret = sgx_aes_ctr_encrypt(
            &enc_key, 
            (const uint8_t*) output_str.c_str(), 
            output_len, 
            aes_ctr, 
            128, 
            (uint8_t*) encrypted_bytes);
        std::string encrypted_str_b64 = sgx_base64::base64_encode((unsigned char*) encrypted_bytes, output_len);
        output_json["output_encrypted"] = encrypted_str_b64;
    }

    client_output = output_json.dump();
    //enclave_log("[ENCLAVE] [JS] [EXECUTE] Encrypted JSON with length %lu is \n%s\n", client_output.length() + 1, client_output.c_str());

    // Disable collecting of resource measurements again
    g_processing = false;
    set_ssa_marker();
    runtime_measurements->tsx_failed = tsx_failed;
    runtime_measurements->tsx_failed_explicit = tsx_failed_explicit;
    runtime_measurements->tsx_failed_conflict = tsx_failed_conflict;
    runtime_measurements->tsx_failed_retry = tsx_failed_retry;
    runtime_measurements->custom_handler_called = custom_handler_called;
    stop_resource_measurements(runtime_measurements);

    // set output size to size and return
    *output_size = client_output.length() + 1; // str length plus \0 at the end
    *measurement_size = sizeof(resource_measurement_t) + output_udata.length() + 1;
    //enclave_log("[ENCLAVE] [JS] [EXECUTE] Script execution done.\n");
    return SGX_SUCCESS;
}

/*
 * Finalizes the script and closes all contexts.
 * Input:
 * Output buffer with given size, measurements buffer
 * 
 * Output:
 * Output intended for client (with given size) and a filled and signed resource measurement metric
*/
JS_STATUS ecall_script_finish(
    char* output, 
    size_t output_length, 
    resource_measurement_t* measurements, 
    size_t measurements_size,
    sgx_ec256_signature_t* measurements_signature){
    enclave_log("[ENCLAVE] [JS] [FINISH] Wrapping up script execution\n");

    if(output_length != client_output.length() + 1){ // str length plus \0 at the end
        enclave_log("ERROR: Given output length and expected length do not match! Aborting.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if(measurements_size != sizeof(resource_measurement_t) + output_udata.length() + 1){
        enclave_log("ERROR: Given measurement length and expected length do not match! Aborting.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    enclave_log("[ENCLAVE] [JS] [FINISH] Calculating resource measurements...\n");
    // allocate struct and set to zero
    resource_measurement_t* calculated = (resource_measurement_t*) malloc(measurements_size);
    memset_s(calculated, measurements_size, 0, measurements_size);

    // Wrap up measurements by doing one last time window update
    uint64_t diff = runtime_measurements->cpu_stop_time - runtime_measurements->previous_allocation_event;
    runtime_measurements->memory_seconds_underreported += runtime_measurements->current_memory * diff;
    runtime_measurements->memory_seconds_overreported += runtime_measurements->current_memory * (diff > 0 ? diff : 1); 
    if(runtime_measurements->current_memory > runtime_measurements->max_memory) 
        runtime_measurements->max_memory = runtime_measurements->current_memory;

    calculated->cpu_time = runtime_measurements->cpu_stop_time - runtime_measurements->cpu_start_time;
    calculated->max_memory = runtime_measurements->max_memory;
    calculated->memory_seconds_underreported = runtime_measurements->memory_seconds_underreported;
    calculated->memory_seconds_overreported = runtime_measurements->memory_seconds_overreported;
    calculated->io_bytes = runtime_measurements->io_bytes;
    calculated->tsx_failed = runtime_measurements->tsx_failed;
    calculated->tsx_failed_explicit = runtime_measurements->tsx_failed_explicit;
    calculated->tsx_failed_conflict = runtime_measurements->tsx_failed_conflict;
    calculated->tsx_failed_retry = runtime_measurements->tsx_failed_retry;
    calculated->custom_handler_called = runtime_measurements->custom_handler_called;

    // Set metadata (tick duration, udata)
    calculated->lambda_tick_duration = SGX_TIMER_TICK_DURATION;
    const char* udata = output_udata.c_str();
    calculated->udata_len = output_udata.length() + 1;
    memcpy(&calculated->udata, udata, calculated->udata_len);

    // Sign measurements
    sgx_ec256_signature_t signature;
    sgx_status_t ret = sgx_ecdsa_sign(
        (uint8_t*) &calculated, 
        measurements_size, // str length plus \0 at the end
        &DATA_BUFFER.resource_signing_private, 
        &signature, 
        ECC_HANDLE);
    if (ret != SGX_SUCCESS) {
        enclave_log("[ENCLAVE] [JS] [FINISH] Failed to sign measurements.\n");
        return ret;
    } else {
        enclave_log("[ENCLAVE] [JS] [FINISH] Measurements signature generated.\n");
    }
    enclave_log("[ENCLAVE] [JS] [FINISH] Calculating resource measurements...done\n");

    memcpy(output, client_output.c_str(), output_length);
    memcpy(measurements, calculated, measurements_size);
    memcpy(measurements_signature, &signature, sizeof(sgx_ec256_signature_t));

    enclave_log("[ENCLAVE] [JS] [FINISH] Calculations done, shutting down enclave\n");

    return SGX_SUCCESS;
}

/**
 * Setup:
 * Creates and initializes the persistent data buffer.
 * Seals it and stores it
 * 
 * Creates DH pubkey for user to connect
 * Creates Signing key to use instead of quotes
 * Creates a Quote over a hash of both pubkeys to publish
 * 
 * TODO: move this whole function into PE. Here, we only need the provision and reload functions
 * 
*/
JS_STATUS ecall_setup(void* buffer, uint32_t buffer_size, sgx_ec256_public_t* signing_pk, sgx_ec256_public_t* dh_pk, sgx_ec256_public_t* resource_pk){

    JS_STATUS ret = SGX_ERROR_UNEXPECTED;

    enclave_log("[ENCLAVE] [SETUP] Initial key setup...\n");

    // Create ECC context and generate keys into our data buffer
    ret = sgx_ecc256_open_context(&ECC_HANDLE);
    if(ret != SGX_SUCCESS){
        enclave_log("[ENCLAVE] [SETUP] Error opening ECC context\n");
        return ret;
    }
    // Signing key pair
    ret = sgx_ecc256_create_key_pair(
            &DATA_BUFFER.signing_private,
            &DATA_BUFFER.signing_public,
            ECC_HANDLE
        );
    if(ret != SGX_SUCCESS){
        enclave_log("[ENCLAVE] [SETUP] Error creating ECC key pair\n");
        return ret;
    }
    enclave_log("[ENCLAVE] [SETUP] Successfully created signing key pair.\n");

    // Public DH key pair
    ret = sgx_ecc256_create_key_pair(
            &DATA_BUFFER.dh_private,
            &DATA_BUFFER.dh_public,
            ECC_HANDLE
        );
    if(ret != SGX_SUCCESS){
        enclave_log("[ENCLAVE] [SETUP] Error creating ECC key pair\n");
        return ret;
    }
    enclave_log("[ENCLAVE] [SETUP] Successfully created DH key pair.\n");

    // Resource measurement signing key pair
    ret = sgx_ecc256_create_key_pair(
            &DATA_BUFFER.resource_signing_private,
            &DATA_BUFFER.resource_signing_public,
            ECC_HANDLE
        );
    if(ret != SGX_SUCCESS){
        enclave_log("[ENCLAVE] [SETUP] Error creating key pair for resource measurements\n");
        return ret;
    }
    enclave_log("[ENCLAVE] [SETUP] Successfully created key pair for signing resource measurements.\n");

    // Now seal the struct
    uint32_t sealed_size = sgx_calc_sealed_data_size(0,sizeof(key_data_t));
    if(buffer_size != sealed_size){
        enclave_log("[ENCLAVE] [SETUP] Buffer size is not equal to expected size (%u != %u (expected)). Aborting.\n", buffer_size, sealed_size);
        return SGX_ERROR_INVALID_PARAMETER;
    }
    ret = sgx_seal_data(0, NULL, sizeof(key_data_t),
                        (uint8_t*)(&DATA_BUFFER), buffer_size, (sgx_sealed_data_t *)buffer);
                        
    memcpy(signing_pk, &(DATA_BUFFER.signing_public), sizeof(sgx_ec256_public_t));
    memcpy(dh_pk, &(DATA_BUFFER.dh_public), sizeof(sgx_ec256_public_t));
    memcpy(resource_pk, &(DATA_BUFFER.resource_signing_public), sizeof(sgx_ec256_public_t));

    // We want to publish a JSON string that contains an inner json with the public keys and an outer json with a quote
    // inner json
    json::JSON public_keys = json::JSON();
    public_keys["session_dh"] = sgx_base64::ecc_pk_to_base64(&DATA_BUFFER.dh_public);
    public_keys["signing_pk"] = sgx_base64::ecc_pk_to_base64(&DATA_BUFFER.signing_public);
    public_keys["measurements_pk"] = sgx_base64::ecc_pk_to_base64(&DATA_BUFFER.resource_signing_public);

    // hash this inner json for quote
    sgx_sha256_hash_t pk_hash;
    std::string public_keys_string = public_keys.dump();
    sgx_sha256_msg((uint8_t*) public_keys_string.c_str(), public_keys_string.length() + 1, &pk_hash);

    // Create a quote that contains the just signed hash as REPORT DATA
    //TODO: Create quote that contains <pk_hash>
    sgx_quote_t received_quote;
    
    // create an outer json
    json::JSON key_output = json::JSON();
    key_output["keys"] = public_keys;
    //key_output["report"] = sgx_base64::report_to_base64(&received_quote);
    // TODO: Enable report printing when received_quote is not empty anymore

    enclave_log("[ENCLAVE] [SETUP] Built output json:\n%s\n", key_output.dump().c_str());

    IS_INITIALIZED = true;
    enclave_log("[ENCLAVE] [SETUP] Data sealed and public keys copied. Done.\n");

    return ret;
}

/* 
 * Provide I/O bindings for Duktape
 * Input is a JSON that defines the target URL and the parameters
 * {
 *  url:<string>,
 *  headers:<json>
 * }
 * 
 * Output is also a JSON with the response body.
 */
static duk_ret_t http_io(duk_context *ctx) {
    std::string input_string = duk_to_string(ctx, 0);
    enclave_log("[ENCLAVE] [JS] [HTTP OCALL] called with %s\n", input_string.c_str());

    // parse jso
    json::JSON input_json = json::JSON::Load(input_string);

    // Assemble web request
    // This can be done with SSL libraries if needed.
    // Here, we are just interested in a simple mock request
    // So we will just send the URL to the untrusted environment

    size_t max_output_size = 1000;
    char* result = (char*) malloc(max_output_size);
    uint64_t result_size;
    ocall_http_io(input_json["url"].ToString().c_str(), result, &result_size, max_output_size);

    enclave_log("[ENCLAVE] [JS] [HTTP OCALL] returning string %s\n", result);

    duk_push_string(ctx, result);

    //Add IO bytes to memory count
    runtime_measurements->io_bytes += input_json.length() + 1 + result_size; // str length plus \0 at the end

    return 1;  /* one return value */
}


void duktape_error(void *udata, const char *msg){
    enclave_log("\nERROR:\n[ENCLAVE] [JS] [DUKTAPE] JS Engine encountered an error:%s\nError content:%s\nERROR END!\n", msg, duk_safe_to_string(ctx, -1));
}

void register_native_functions(duk_context *ctx){
    duk_push_c_function(ctx, http_io, 1 /*nargs*/);
    duk_put_global_string(ctx, "http_io");
}

#if defined(__cplusplus)
}
#endif
