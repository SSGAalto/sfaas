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

#include "elogger.h"
#include "resources.h"

extern volatile int tsx_counter;

void start_resource_measurements(RuntimeMeasurements* mm){
    mm -> active = true;
    mm -> cpu_start_time = tsx_counter;
    mm -> previous_allocation_event = mm->cpu_start_time; //start event counts as beginning of measurements
}

void stop_resource_measurements(RuntimeMeasurements* mm){
    mm -> active = false;
    mm -> cpu_stop_time = tsx_counter;
}

size_t get_pointer_size(void* pointer){
    if(pointer == NULL) return 0;
    return *((size_t*)pointer-sizeof(size_t)/8);
}

void update_measurements(RuntimeMeasurements* mm, uint64_t timestamp){
    if(mm->active){ 
        uint64_t diff = timestamp - mm->previous_allocation_event;
        // Underreport means factor of 0 if no time has passed since last alllocation event
        mm->memory_seconds_underreported += mm->current_memory * diff;
        //Overreport means factor of 1 if no time has passed since last allocation event
        mm->memory_seconds_overreported += mm->current_memory * (diff > 0 ? diff : 1); 
        if(mm->current_memory > mm->max_memory) mm->max_memory = mm->current_memory;
    }

    // Set last event to now
    mm->previous_allocation_event = timestamp;
}

/**
 * Resource-aware memory functions.
 * These can be passed to the duktape heap allocator
 */
void* resource_alloc(void *udata, duk_size_t size){
    // allocate memory
    void * pointer = malloc(size);
    size_t allocated_size = get_pointer_size(pointer);

    // get current timestamp
    uint64_t timestamp = tsx_counter;

    // Cast user data to object
    RuntimeMeasurements* mm = (RuntimeMeasurements*) udata;

    // Update previous window if we are counting
    update_measurements(mm, timestamp);

    // Increase current memory
    mm->current_memory += allocated_size;

    //debug_log("[ENCLAVE] [MEMORY] [NOTABLE DEBUGGING EVENT] ALLOC %lu %p at time %lu. Counting:%d. Current memsecs %lu or %lu and current memory %lu. Previous event was at %lu\n", allocated_size, pointer, timestamp, mm->active, mm->memory_seconds_underreported, mm->memory_seconds_overreported, mm->current_memory, mm->previous_allocation_event);


    return pointer;
}

/*
 * The realloc is the most complex for our resource measurements.
 * We need to take the most recent transaction list (ALLOC, RESIZE, FREE operations) from
 * its old pointer and move it to the new pointer after adding the current operation.
 * This is so that we can track all operations across pointers (and can properly account for frees).
*/
void* resource_realloc(void *udata, void *old_pointer, duk_size_t size){
    // Run realloc
    size_t old_size = get_pointer_size(old_pointer);
    void* new_pointer = realloc(old_pointer, size);
    size_t new_size = get_pointer_size(new_pointer);

    // Take current timestamp
    uint64_t timestamp = tsx_counter;

    // Cast user data to object
    RuntimeMeasurements* mm = (RuntimeMeasurements*) udata;
        
    //update previous window
    update_measurements(mm, timestamp);

    // subtract old size from current memory and add new size
    mm->current_memory = mm->current_memory + new_size - old_size;

    //debug_log("[ENCLAVE] [MEMORY] [NOTABLE DEBUGGING EVENT] REALLOC %lu %p to %p %lu at %lu. Counting:%d. Current memsecs %lu or %lu and current memory %lu. Previous event was at %lu\n", old_size, old_pointer, new_pointer, new_size, timestamp, mm->active, mm->memory_seconds_underreported, mm->memory_seconds_overreported, mm->current_memory, mm->previous_allocation_event);

    return new_pointer;
}

void resource_free(void *udata, void *pointer){
    // perform free
    size_t old_size = get_pointer_size(pointer);
    free(pointer);

    // Take current timestamp
    uint64_t timestamp = tsx_counter;

    // Cast user data to object and check if active
    RuntimeMeasurements* mm = (RuntimeMeasurements*) udata;

    //update previous window
    update_measurements(mm, timestamp);

    // subtract old size from current memory
    mm->current_memory = mm->current_memory - old_size;
    
    
    //debug_log("[ENCLAVE] [MEMORY] [NOTABLE DEBUGGING EVENT] FREE %p of size %lu at %lu. Counting:%d. Current memsecs %lu or %lu and current memory %lu. Previous event was at %lu\n", pointer, old_size, timestamp, mm->active, mm->memory_seconds_underreported, mm->memory_seconds_overreported, mm->current_memory, mm->previous_allocation_event);
}

