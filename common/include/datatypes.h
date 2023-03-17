#ifndef DATATYPES_H_
#define DATATYPES_H_

#include "sgx_tseal.h"
#include "sgx_tcrypto.h"


// Define the tick duration used by the timing thread
#define SGX_TIMER_TICK_DURATION 1000


#define PUBKEY_SIZE 2*SGX_ECP256_KEY_SIZE

// Error codes
#define SGX_JS_MK_ERROR(x)              (0x00011000|(x))
typedef uint32_t JS_STATUS;
typedef enum _js_status_t
{
    /* JS Enclave has not been initialized */
    SGX_JS_ERROR_NOT_INITIALIZED   = SGX_JS_MK_ERROR(0x01),
    SGX_JS_ERROR_CONTEXT_ERROR     = SGX_JS_MK_ERROR(0x10),
    SGX_JS_ERROR_SCRIPT_HASH_MISMATCH = SGX_JS_MK_ERROR(0x20),

} sgx_js_status_t;

// Actual data sent over to ME
typedef struct _key_data_t {
    // dh key for session establishment
    sgx_ec256_private_t dh_private;
    sgx_ec256_public_t dh_public;
    // signing key
    sgx_ec256_private_t signing_private;
    sgx_ec256_public_t signing_public;
    // signing key for resource measurements
    sgx_ec256_private_t resource_signing_private;
    sgx_ec256_public_t resource_signing_public;
} key_data_t;

typedef struct _resource_measurement {
    // time for cpu
    uint64_t cpu_time;

    // memory*seconds
    // Underreported means time window does not count when time window is 0 (same window as last allocation)
    // Overreported means time window is 1 if same window as last allocation
    uint64_t memory_seconds_underreported;
    uint64_t memory_seconds_overreported;

    // The overall maximum over all alloc calls
    uint64_t max_memory;

    uint64_t tsx_failed;
    uint64_t tsx_failed_explicit;
    uint64_t tsx_failed_conflict;
    uint64_t tsx_failed_retry;
    uint64_t custom_handler_called;

    uint64_t io_bytes;

    // Lambda value to report the tick duration
    uint64_t lambda_tick_duration;

    // User data appended to this resource measurement
    size_t udata_len;
    uint8_t udata[];
} resource_measurement_t;

#endif
