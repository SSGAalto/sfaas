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
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include <curl/curl.h>

#include <unistd.h>
#include <pwd.h>
#include <libgen.h>

#define MAX_PATH FILENAME_MAX
#define PSE_RETRIES 3

#include <sgx_urts.h>
#include "enclave_u.h"

#include <boost/program_options.hpp>
#include <algorithm>

#include <numeric>
#include <chrono>
#include <thread>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <iterator>

#include <fcntl.h>

#include <sgx_tseal.h>   // For seal defines
#include <sgx_error.h>   /* sgx_status_t */
#include <sgx_eid.h>     /* sgx_enclave_id_t */

#include <sys/mman.h>

// #define SGXSTEP

#ifdef SGXSTEP
#define SGX_STEP_TIMER_INVERVAL 1000
#include "libsgxstep/apic.h"
#include "libsgxstep/enclave.h"
#include "libsgxstep/sched.h"
#include "libsgxstep/config.h"
#endif

#include "datatypes.h"
#include "sgx_errors.h"
#include "tsx.h"
#include "logger.h"

#include "ra.h"
#include "nrt_ra.h"
#include "nrt_ukey_exchange.h"

#include "network_types.h"
#include "TcpConnection.h"
#include "socket.h"

#include "ocalls.h"

#define ENCLAVE_PATH "build/enclave/enclave.signed.so"

static struct logger* l = NULL;

struct arguments {
    char* progname;
    std::string pe_ip;
    std::string pe_port;
    std::string faas_port;
    std::string provision;
    std::string reload;
    std::string execute;
    std::string execute_input;
    bool logging;
    bool logging_debug;
    bool eval_mode;
};

struct arguments args;

using namespace boost::program_options;
using namespace std;
using namespace network;
using boost::asio::ip::tcp;

// Networking
boost::asio::io_service g_io_service;
std::map<std::string, ra_socket_t*> g_ra_sockets;

/* Global EID shared by multiple threads */
sgx_enclave_id_t g_eid = 0;

// Required size for init buffer
uint32_t g_required_size;

// Async Exit Pointer counter
int aep_fired = 0;

// Pointer to g_processing inside enclave to revoke access rights
void* g_p_processing;

std::thread* counter_thread;

bool provisioning_done = false;

/*
 * Utility and debugging functions 
 */
void ocall_print_byte_array(const void* mem, uint32_t len)
{
    printf("Byte array");
    fflush(stdout);
    if(!mem || !len)
    {
        printf("\n( null )\n");
        return;
    }
    uint8_t *array = (uint8_t *)mem;
    printf("%u bytes:\n{\n", len);
    uint32_t i = 0;
    for(i = 0; i < len - 1; i++)
    {
        printf("0x%x, ", array[i]);
        if(i % 8 == 7) printf("\n");
    }
    printf("0x%x ", array[i]);
    printf("\n}\n");
}

void print_buffer(void* pubkey, size_t size){
    for (uint32_t i = 0; i < size ; i++){
        printf("%X", ((uint8_t *) pubkey)[i]);
    }
    printf("\n");
}

void aep_cb_func(uint64_t erip)
{
    aep_fired++;
}

void signal_handler(int signal)
{
    mprotect(g_p_processing, 4096, PROT_READ | PROT_WRITE);
}

void counter_fn(void)
{
    #ifdef SGXSTEP
    // claim_cpu(1);
    #endif
    sgx_status_t ret = SGX_SUCCESS;
    int status = SGX_SUCCESS;
    void* counter_thread_data = NULL;
    uint64_t cssa;

    ret = ecall_counter( g_eid, &status );

    log_print( l, "Counter returned.\n" );

    if( (status != SGX_SUCCESS) || (ret != SGX_SUCCESS) ) {
        log_error( l, "Counter returned with error.\n" );
        return;
    }
}

int parse_arguments(int argc, char *argv[], struct arguments *args, variables_map *vm)
{
    args->progname = argv[0];
    try{
        options_description desc{"Options"};
        desc.add_options()
          ("help,h", "Help screen")
          ("new,n", "Generates new keys")
          ("provision,p", value<std::string>(&(args->provision)),
           "Restores the keys from a provisioning enclave")
          ("reload,r", value<std::string>(&(args->reload)),
           "Reloads the keys from a file")
          ("verbose,v", "Enable logging mode")
          ("debug,d", "Enable debugging mode. Requires verbose mode")
          ("p_ip", value<std::string>(&(args->pe_ip))->default_value("127.0.0.1"),
           "IP address of Provisioning Enclave")
          ("pe_port", value<std::string>(&(args->pe_port))->default_value("1300"),
           "Port of Provisioning Enclave")
          ("execute,x", value<std::string>(&(args->execute)),
           "Execute a javascript file given by a path")
          ("server,s", value<std::string>(&(args->faas_port))->default_value("7000"),
           "Server port for serving FaaS requests")
          ("input,i", value<std::string>(&(args->execute_input)),
           "Input file given to the execution as json")
           ("eval,e", "Turns on evaluation mode that disables printing and only outputs a single JSON with the measurement results to stdout");


        store(parse_command_line(argc, argv, desc), *vm);
        notify(*vm);

        if (vm->count("help") || argc == 1){
          std::cout << desc << '\n';
          return 1;
        }
    }
    catch (const error &ex){
        std::cerr << ex.what() << '\n';
        return -1;
    }
    return 0;
}

void setup(struct arguments *args, const variables_map *vm)
{
    // Setup: Changing dir to where the executable is.
    char absolutePath [MAX_PATH];
    char *ptr = NULL;

    ptr = realpath(dirname(args->progname), absolutePath);

    if( chdir(absolutePath) != 0)
    		abort();

    // Store logging levels
    if(vm->count("verbose")) args->logging = true;
    if(vm->count("debug")) args->logging_debug = true;

    // Show an error if debug is allowed but verbose is not
    if(args->logging_debug & !args->logging)
        throw std::logic_error(std::string("WARNING: -d also requires -v flag for logging"));

    curl_global_init( CURL_GLOBAL_ALL );

    if(vm->count("eval")) args->eval_mode = true;
}

void setup_apic()
{
    #ifdef SGXSTEP
    // claim_cpu(1);
    prepare_system_for_benchmark(PSTATE_PCT);
    print_system_settings();

    register_aep_cb(aep_cb_func);
    register_enclave_info(/*edbgrd_rip=*/ 0);
    print_enclave_info();
    /*print_tcs( (struct tcs_type*)sgx_get_tcs() );*/

    apic_timer_oneshot();
    apic_hook();
    #endif
}

void restore_apic()
{
    #ifdef SGXSTEP
    apic_timer_deadline();
    #endif
}

void setup_enclave(const struct arguments *args)
{
    JS_STATUS retval = SGX_SUCCESS;
    int status;
    sgx_status_t ret;
    void *worker_thread = NULL;
    uint64_t cssa;

    // Set logging level if it is true
    if(args->logging){
        retval = ecall_set_logging(g_eid, args->logging, args->logging_debug);
    }
    if(retval != SGX_SUCCESS){
        log_error(l, "Error setting logging level: %X \n Aborting...\n", retval);
        exit(EXIT_FAILURE);
    }

    // read out required sealing size
    retval = ecall_get_persistent_buffer_size(g_eid, &g_required_size);
    if(retval != SGX_SUCCESS){
        log_error(l, "Error receiving expected buffer size! %X \n Aborting...\n", retval);
        exit(EXIT_FAILURE);
    }

    log_print(l, "Worker thread: %lu\n", worker_thread);
    ret = ecall_set_worker_ssa( g_eid, &status, &worker_thread, &cssa );
    if( (status != SGX_SUCCESS) || (ret != SGX_SUCCESS) ) {
        log_error(l, "Failed to setup SSA\n");
        print_error_message((sgx_status_t)status);
        print_error_message(ret);
    }
    log_print(l, "Worker thread: %p\n", worker_thread);

    ecall_tsx_get_addr( g_eid, &g_p_processing );
    counter_thread = new std::thread(counter_fn);
    setup_apic();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
}

static int store_keys( void* buff )
{
    // Store buffer on disk
    FILE *fp;
    fp = fopen(args.provision.c_str(), "wb");
    if (fp == NULL){
        log_error(l, "[Provision] Error: Could not open file \"%s\" to store provisioned keys."
            "Aborting...\n", args.provision);
        return -1;
    }

    size_t write_num = fwrite(buff, 1, g_required_size, fp);
    if (write_num != g_required_size){
        log_error(l, "[Provision] Warning: Failed to save provisioned keys \"%s\".\n", args.provision);
        return -1;
    }

    fclose(fp);

    return 0;
}

static int handle_remote_message(network::TcpConnection *conn, message_t *msg)
{
    nrt_ra_request_header_t* ra_msg;
    nrt_ra_msg_quote_t* quote_msg;
    quote_t* quote;
    ra_socket_t *ra_socket = g_ra_sockets[ conn->to_string() ];
    void *buff;
    sgx_status_t ret;
    JS_STATUS retval;

    int max_len = sizeof(key_data_t);
    uint32_t res_len = 0;
    uint8_t *key_data_msg;

    log_print(l, "[Provision] Received remote message.\n");

    switch(msg->type) {

      case NETWORK_RA_MESSAGE_QUOTE_RESPONSE:
        /*
         * The remote enclave replied with its quote.
         * Ready to send the migration data.
         */

        ra_msg = (nrt_ra_request_header_t*) msg->data_plaintext;
        if( ra_msg->type != TYPE_NRT_RA_MSG_QUOTE ) {
            log_error(l, "[Provision] [RE] Incoming response message does not contain a quote.\n");
            break;
        }
        
        log_print(l, "[Provision] [RE] Received Quote from PE\n");

        // Retrieve, verify, and store quote
        quote_msg = (nrt_ra_msg_quote_t*)((uint8_t*)ra_msg +
                                          sizeof(nrt_ra_request_header_t));
        quote = (quote_t*) malloc( sizeof(quote_t) );
        memcpy(quote, quote_msg->quote, sizeof(quote_t));
        ra_verify_quote(quote);
        // g_ra_quotes[ conn->to_string() ] = quote;

        ret = nrt_ra_set_gb( ra_socket->context, g_eid, nrt_ra_set_gb_trusted,
                             &(quote_msg->g_a) );
        if( ret != SGX_SUCCESS ) {
          printf("[Provision] [RE] Could not set g_b.\n");
          print_error_message((sgx_status_t)ret);
          return -1;
        }

        // Allocate buffer for sealed persistent data
        buff = (void*) malloc(g_required_size);
        
        // Perform ecall with encrypted data, and buffer to fill with sealed data
        ret = ecall_initialize_provision(g_eid, &retval, ra_socket->context,
                buff, g_required_size, msg->data_encrypted, msg->size_encrypted);

        if( ret != SGX_SUCCESS || retval != SGX_SUCCESS ) {
            log_error(l, "Error during initialize provisioned key data %x "
               "(System) and %x (Enclave)", ret, retval);
        }

        if( store_keys( buff ) == -1 ) {
            return -1;
        }

        free(buff);

        // cleanup
        // TODO Figure out proper cleanup actually, too many free here
        // causes exception abort

        free(g_ra_sockets[ conn->to_string() ]);
        g_ra_sockets.erase(conn->to_string());
        conn->socket().close();

        log_print(l, "[Provision] Provisioning done\n");
        provisioning_done = true;

        break;

      default:
        log_error(l, "[REMOTE MESSAGE] Unknown incoming message: %X\n", msg->type);
    }

    return -1;
}

int operation_provision(const char* pe_ip, const char* pe_port)
{
    JS_STATUS retval = SGX_SUCCESS;
    sgx_status_t ret;

    log_print(l, "[Provision] Restoring keys from provisioning enclave...\n");

    // For some reason if we create resolver only in ra_send_quote_to
    // the constructor hangs on a mutex
    tcp::resolver resolver(g_io_service);
    tcp::resolver::query query(pe_ip, pe_port);
    tcp::resolver::iterator iter = resolver.resolve(query);

    // Set up remote attestation
    ra_socket_t* ra_socket = (ra_socket_t*) malloc( sizeof(ra_socket_t) );
    memset(ra_socket, 0, sizeof(ra_socket_t));
    if( ra_send_quote_to( g_eid, pe_ip, pe_port, ra_socket, &g_io_service ) != 0 ) {
        log_error(l, "[Provision] Could not send quote.\n");
        return -1;
    };

    log_print(l, "[Provision] Contacted provisioning enclave, waiting for response...\n");

    g_ra_sockets[ ra_socket->conn->to_string() ] = ra_socket;
    ra_socket->conn->receive_msg( handle_remote_message );

    return 0;
}

char* execute_char;
char* input_char;

void operation_execute(const char* execute_file, const char* input_file);
void operation_init(const char* execute_file, const char* input_file);
int sgx_process(char* buf, int buf_len, uint8_t *res, uint32_t *res_len)
{
  operation_execute(execute_char, input_char);
  *res_len = 2;
  memcpy(res, "OK", 2);
  return 0;
}

#define BUF_SIZE 4096
#define HOSTNAME_SIZE 255
int handle_client(int sd)
{
    char buf[BUF_SIZE] = {0};
    uint8_t res[1024];
    uint32_t res_len = 1024;
    int n = 0, ret = 0;

    log_print(l, "New client connected\n");
    while( ret == 0 )
    {
        memset(buf, 0, BUF_SIZE);
        n = 0;
        if( (ret = read(sd, &buf[n], BUF_SIZE-1)) == -1 ) {
            log_error(l, "Error reading from client\n");
            perror("read");
            close(sd);
            return ret;
        }

        n = n + ret;
        if( n == 0 )
            break;

        if( (ret = sgx_process( buf, n, res, &res_len )) == 0 ) {
          write_all(sd, res, res_len);
        }
    }

    close(sd);
    operation_init(execute_char, input_char);

    log_print(l, "Disconnect\n");
    return ret;
}

int server_socket(const char* hostname, in_port_t port)
{
    int sd;

    if( (sd = init_socket(hostname, port, true, NULL)) == -1 ){
        log_error(l, "Socket init failed.\n");
        return -1;
    }

    return sd;
}

int operation_server(int faas_port)
{
    int ret;
    char hostname[HOSTNAME_SIZE] = "localhost";
    in_port_t port = faas_port;
    int server_sd = -1;

    server_sd = server_socket(hostname, port);
    if( server_sd == -1 ) exit(EXIT_FAILURE);

    if( init_tcp_server( server_sd ) == -1 ){
        log_error(l, "Could not initiate the server.\n");
        perror("init_tcp_server");
        exit( EXIT_FAILURE );
    }

    if( (ret = accept_tcp_connections( server_sd, handle_client )) == -1 ){
        log_error(l, "Could not accept a new connection.\n");
        perror("accept_tcp_connections");
    }

    shutdown_logger(l);
    return 0;
}

void operation_new()
{
    JS_STATUS retval = SGX_SUCCESS;
    sgx_status_t ret;

    log_print(l, "[Setup] Generating new keys...\n");

    //TODO: Move this into PE
    void* buff = (void*) malloc(g_required_size);

    sgx_ec256_public_t signing_pk;
    sgx_ec256_public_t dh_pk;
    sgx_ec256_public_t resource_pk;

    // Call gen keys
    // mprotect(g_p_processing, 4096, PROT_NONE);
    // signal(SIGSEGV, signal_handler);
    ret = ecall_setup(g_eid, &retval, buff, g_required_size,
        &signing_pk, &dh_pk, &resource_pk);
    if(retval != SGX_SUCCESS) {
        log_print(l, "[Setup] Error during setup! 0x%x", retval);
    }
    if(ret != SGX_SUCCESS) {
        log_print(l, "[Setup] Error during setup! 0x%x", retval);
    }

    log_print(l, "[Setup] Generated signing key:");
    print_buffer(&signing_pk, sizeof(sgx_ec256_public_t));

    log_print(l, "[Setup] Generated DH key:");
    print_buffer(&dh_pk, sizeof(sgx_ec256_public_t));

    log_print(l, "[Setup] Generated resources key:");
    print_buffer(&resource_pk, sizeof(sgx_ec256_public_t));

    log_print(l, "[Setup] Key generation done\n");

    store_keys( buff );

        free(buff);
}

void operation_reload(const char* reload_file)
{
    JS_STATUS retval = SGX_SUCCESS;
    sgx_status_t ret;

    log_print(l, "[Reload] Reloading keys from sealed buffer.\n");

    // allocate buffer for sealed persistent data
    void* buff = (void*) malloc(g_required_size);

    // Read from file
    log_print(l, "[Reload] Reading file...\n");
    FILE *fp;
    fp = fopen(reload_file, "rb");
    if (fp == NULL) {
        log_error(l, "Error: Could not open the sealed key buffer file \"%s\". Aborting...\n",
            reload_file);
        exit(EXIT_FAILURE);
    } else {
        size_t read_num = fread(buff, 1, g_required_size, fp);
        if (read_num == 0 || read_num != g_required_size) {
            log_error(l, "Warning: Invalid sealed data read from \"%s\".!!! Aborting...", reload_file);
            exit(EXIT_FAILURE);
        }
        fclose(fp);
        log_print(l, "File successfuly read.\n");
    }

    // Restore keys in enclave
    ret = ecall_initialize_reload(g_eid, &retval, buff, g_required_size);

    // free buffer
    free(buff);

    if(retval != SGX_SUCCESS){
        log_error(l, "[Reload] Error during initialize! 0x%x\n", retval);
    } else {
        log_print(l, "[Reload] Successfully restored keys from sealed buffer.\n");
    }
}

string json_input;
void operation_init(const char* execute_file, const char* input_file)
{
    JS_STATUS retval = SGX_SUCCESS;
    sgx_status_t ret;

    string js_script;
    ifstream script_file(execute_file, ios::in | ios::binary);
    if(script_file){
        script_file.seekg(0, ios::end);
        js_script.resize(script_file.tellg());
        script_file.seekg(0, ios::beg);
        script_file.read(&js_script[0], js_script.size());
        script_file.close();
    } else {
        log_error(l, "[Execute] Warning: Failed to open the JS script file \"%s\".\n", execute_file);
        exit(EXIT_FAILURE);
    }

    ifstream json_file(input_file, ios::in | ios::binary);
    if(json_file){
        json_file.seekg(0, ios::end);
        json_input.resize(json_file.tellg());
        json_file.seekg(0, ios::beg);
        json_file.read(&json_input[0], json_input.size());
        json_file.close();
    } else {
        log_error(l, "[Execute] Warning: Failed to open the JS JSON file \"%s\".\n", input_file);
        exit(EXIT_FAILURE);
    }

    auto script_start = std::chrono::high_resolution_clock::now();
    ret = ecall_script_init(g_eid, &retval, js_script.c_str(), js_script.length()+1);
    auto script_end = std::chrono::high_resolution_clock::now();
    if( (ret != SGX_SUCCESS) || (retval != SGX_SUCCESS) ) {
      log_error(l, "[Execute] Error at script init.\n");
      print_error_message(ret);
      print_error_message((sgx_status_t)retval);
      exit(EXIT_FAILURE);
    }
}

void operation_execute(const char* execute_file, const char* input_file)
{
    JS_STATUS retval = SGX_SUCCESS;
    sgx_status_t ret;

    size_t script_output_length;
    size_t measurements_output_length;
    auto run_start = std::chrono::high_resolution_clock::now();
    ret = ecall_script_run(g_eid, &retval, json_input.c_str(), &script_output_length, &measurements_output_length);
    auto run_end = std::chrono::high_resolution_clock::now();
    if( (ret != SGX_SUCCESS) || (retval != SGX_SUCCESS) ) {
      log_error(l, "[Execute] Error at script run.\n");
      print_error_message(ret);
      print_error_message((sgx_status_t)retval);
      exit(EXIT_FAILURE);
    }

    log_print(l, "[Execute] Script finished execution. Output has size %lu. Finishing now...\n",
        script_output_length);

    char* script_output = (char*) malloc(script_output_length);
    resource_measurement_t* resource_measurements = (resource_measurement_t*) malloc(measurements_output_length);
    sgx_ec256_signature_t resource_measurements_signature;
    auto finish_start = std::chrono::high_resolution_clock::now();
    ecall_script_finish(g_eid, &retval,
        script_output, script_output_length, resource_measurements, measurements_output_length, &resource_measurements_signature);
    auto finish_end = std::chrono::high_resolution_clock::now();

    log_print(l, "[Execute] Script output is \n%s\n", script_output);
    log_print(l, "[Execute] The script reported a runtime of %lu ticks,"
        " a maximum memory consumption of %lu byte, %lu or %lu byte-ticks, and %lu I/O bytes.\n",
        resource_measurements->cpu_time, resource_measurements->max_memory,
        resource_measurements->memory_seconds_underreported,
        resource_measurements->memory_seconds_overreported, resource_measurements->io_bytes);
    log_print(l, "[Execute] TSX failed %lu, explicit %lu, conflict %lu, retry %lu.\n"
        "Custom handler called %lu\n",
        resource_measurements->tsx_failed,
        resource_measurements->tsx_failed_explicit,
        resource_measurements->tsx_failed_conflict,
        resource_measurements->tsx_failed_retry,
        resource_measurements->custom_handler_called);
    log_print(l, "[Execute] AEP counter %lu\n", aep_fired);
    log_print(l, "Tick counter was set to %lu\n", resource_measurements->lambda_tick_duration);

    typedef std::chrono::nanoseconds accuracy;
    // size_t script_duration = std::chrono::duration_cast<accuracy>(script_end - script_start).count();
    size_t run_duration = std::chrono::duration_cast<accuracy>(run_end - run_start).count();
    size_t finish_duration = std::chrono::duration_cast<accuracy>(finish_end - finish_start).count();

    // log_print(l, "[EXECUTE] Durations for Script, Run, and Finish were: %lu, %lu, and %lu\n", script_duration, run_duration, finish_duration );

    if(args.eval_mode){
        // Print out a single json
        json::JSON log_output = json::JSON();
        log_output["duration_script"] = 0;
        log_output["duration_run"] = run_duration;
        log_output["duration_finish"] = finish_duration;
        log_output["cpu"] = resource_measurements->cpu_time;
        log_output["memsecs_underreported"] = resource_measurements->memory_seconds_underreported;
        log_output["memsecs_overreported"] = resource_measurements->memory_seconds_overreported;
        log_output["max_mem"] = resource_measurements->max_memory;
        log_output["io"] = resource_measurements->io_bytes;
        log_output["tsx"] = resource_measurements->tsx_failed;
        log_output["aep"] = aep_fired;
        std::cout << log_output.dump() << std::endl;
    }
    free(script_output);
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    variables_map vm;
    JS_STATUS retval = SGX_SUCCESS;
    if( parse_arguments(argc, argv, &args, &vm) != 0 )
        return -1;

    // Turn off logger if we are in eval mode
    if(vm.count("eval")) 
        l = init_logger(NULL, NULL, NULL, "Main");
    else
        l = init_logger(stdout, stderr, stderr, "Main");

    const char* pe_ip_char = args.pe_ip.c_str();
    const char* pe_port_char = args.pe_port.c_str();
    execute_char = (char*)args.execute.c_str();
    input_char = (char*)args.execute_input.c_str();
    const char* provision_char = args.provision.c_str();
    const char* reload_char = args.reload.c_str();

    setup(&args, &vm);

    boost::asio::io_service::work work(g_io_service);
    std::thread thread(boost::bind(&boost::asio::io_service::run, &g_io_service));

    /*
     * Start enclave
     */
    log_print(l, "Starting enclave.\n");
    retval = create_enclave(ENCLAVE_PATH, &g_eid);
    if( retval != SGX_SUCCESS ) {
        log_error(l, "Failed to create an enclave %x\n", retval);
        print_error_message((sgx_status_t)retval);
        exit(EXIT_FAILURE);
    }

    setup_enclave(&args);

    /*
    * Process the program arguments.
    * There are three initializations:
    *  1) Generate new keys (setup)
    *  2) Provision pre-generated keys from provisioning enclave
    *  3) Reload sealed buffer (that was initialized once already)
    */

    if (vm.count("new"))
      operation_new();
    
    if (vm.count("provision")){
        // Start provisioning
        if( operation_provision(pe_ip_char, pe_port_char) == -1 )
          return -1;
        // And block execution until provisioning is done
        while(!provisioning_done){
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    if (vm.count("reload"))
      operation_reload(reload_char);

    if (vm.count("execute"))
    {
      operation_init(execute_char, input_char);
      operation_execute(execute_char, input_char);
    }

    if (vm.count("server"))
    {
      // operation_init(execute_char, input_char);
      //operation_server(std::stoi(args.faas_port));
    }

    // shutdown the enclave
    log_print(l, "Shutting down\n");
    ecall_shutdown(g_eid, &retval);
    log_print(l, "Done.\n");

    shutdown_logger(l);

    g_io_service.stop();
    thread.join();
    counter_thread->join();
    delete counter_thread;
    sgx_destroy_enclave(g_eid);
    return 0;
}

