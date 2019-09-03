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

#include <string.h>
#include <stdio.h>

#include "sgx_uae_service.h"

#include "enclave_u.h"

/*
 * Create the enclave instance
 * Call sgx_create_enclave to initialize an enclave instance
 */
sgx_status_t create_enclave(const char* enclave_filename, sgx_enclave_id_t *eid)
{
    int launch_token_update = 0;
    sgx_launch_token_t launch_token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Debug Support: set 2nd parameter to 1 */
    return sgx_create_enclave(enclave_filename,
                              SGX_DEBUG_FLAG,
                              &launch_token,
                              &launch_token_update,
                              eid, NULL);
}

sgx_status_t enclave_process(sgx_enclave_id_t eid,
                             const uint8_t *data,
                             int data_len,
                             uint8_t *res_buf,
                             uint32_t *res_len)
{
    sgx_status_t status = SGX_SUCCESS;
    sgx_status_t ret = SGX_SUCCESS;
    uint32_t max_len = *res_len;

    /* TODO Call the JS script run here */
    // ret = ecall_process(eid, &status, data, data_len, res_buf, max_len, res_len);

    if (ret != SGX_SUCCESS) {
        return ret;
    }
    if (status != SGX_SUCCESS) {
        return (sgx_status_t)status;
    }

    return SGX_SUCCESS;
}

sgx_status_t enclave_counter(sgx_enclave_id_t eid,
                             uint8_t *res_buf,
                             uint32_t *res_len)
{
    sgx_status_t status = SGX_SUCCESS;
    sgx_status_t ret = SGX_SUCCESS;
    uint32_t max_len = *res_len;

    /* TODO Call the JS script run here */
    // ret = ecall_counter(eid, &status, res_buf, max_len, res_len);

    if (ret != SGX_SUCCESS) {
        return ret;
    }
    if (status != SGX_SUCCESS) {
        return (sgx_status_t)status;
    }

    return SGX_SUCCESS;
}

static const sgx_spid_t g_spid = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};
