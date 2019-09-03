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

#ifndef _JS_ENCLAVE_RESOURCES_H_
#define _JS_ENCLAVE_RESOURCES_H_

#include <map>
#include <utility>

#include "duktape.h"
#include "datatypes.h"

#if defined(__cplusplus)
extern "C" {
#endif

typedef std::pair<uint64_t, duk_size_t> resource_entry;

class RuntimeMeasurements
{
public:

    bool active;
    uint64_t previous_allocation_event;
    uint64_t current_memory;
    
    // time for cpu
    uint64_t cpu_start_time;
    uint64_t cpu_stop_time;

    // memory*seconds
    // Underreported means time window does not count when time window is 0 (same window as last allocation)
    // Overreported means time window is 1 if same window as last allocation
    uint64_t memory_seconds_underreported;
    uint64_t memory_seconds_overreported;

    // The overall maximum encountered at any given time
    uint64_t max_memory;

    uint64_t tsx_failed;
    uint64_t tsx_failed_explicit;
    uint64_t tsx_failed_conflict;
    uint64_t tsx_failed_retry;
    uint64_t custom_handler_called;

    uint64_t io_bytes;
};

void start_resource_measurements(RuntimeMeasurements* mm);
void stop_resource_measurements(RuntimeMeasurements* mm);

void* resource_alloc(void *udata, duk_size_t size);
void* resource_realloc(void *udata, void *old_pointer, duk_size_t size);
void resource_free(void *udata, void *pointer);

#if defined(__cplusplus)
}
#endif


#endif
