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

#include "logger.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

struct logger* init_logger(FILE* print_file, FILE* debug_file, FILE* error_file,
                           const char* module)
{
  struct logger* l = (struct logger*) malloc(sizeof(struct logger));
  l->f_print = print_file;
  l->f_debug = debug_file;
  l->f_error = error_file;
  strcpy(l->module, module);
  return l;
}

void log_print(const struct logger* l, const char* format, ...)
{
  if( l->f_print == NULL ) return;
  va_list arg;
  struct timeval now;
  gettimeofday(&now, 0);
  fprintf(l->f_print, "[%ld.%ld] %s: ", now.tv_sec, now.tv_usec, l->module);
 
  va_start(arg, format);
  vfprintf(l->f_print, format, arg);
  va_end(arg);
}

#define DEBUG_LOG
void log_debug(const struct logger* l, const char* format, ...)
{
#ifdef DEBUG_LOG
  if( l->f_debug == NULL ) return;
  va_list arg;
  struct timeval now;
  gettimeofday(&now, 0);
  fprintf(l->f_debug, "\033[95m [%u.%02u] %s: \033[0m",
          (unsigned int)now.tv_sec, (unsigned int)now.tv_usec, l->module);

  va_start(arg, format);
  vfprintf(l->f_debug, format, arg);
  va_end(arg);
  fprintf(l->f_debug, "\033[0m");
#endif
}

void log_error(const struct logger* l, const char* format, ...)
{
  if( l->f_error == NULL ) return;
  va_list arg;
  struct timeval now;
  gettimeofday(&now, 0);
  fprintf(l->f_error, "\033[91m [%u.%02u] %s: \033[0m",
          (unsigned int)now.tv_sec, (unsigned int)now.tv_usec, l->module);
  va_start(arg, format);
  vfprintf(l->f_error, format, arg);
  va_end(arg);
}

void shutdown_logger(struct logger* l)
{
  free(l);
}

// Prints an array of bytes in hexademical format
void print_byte_array(
    FILE *file, const void *mem, uint32_t len)
{
    if(!mem || !len)
    {
        fprintf(file, "\n( null )\n");
        return;
    }
    uint8_t *array = (uint8_t *)mem;
    fprintf(file, "%u bytes:\n{\n", len);
    uint32_t i = 0;
    for(i = 0; i < len - 1; i++)
    {
        fprintf(file, "0x%x, ", array[i]);
        if(i % 8 == 7) fprintf(file, "\n");
    }
    fprintf(file, "0x%x ", array[i]);
    fprintf(file, "\n}\n");
}

