#include "ocalls.h"

#include <unistd.h>

/* OCall functions */
void ocall_log(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}

size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream) {
    std::string data((const char*) ptr, (size_t) size * nmemb);
    *((std::stringstream*) stream) << data << std::endl;
    return size * nmemb;
}

void ocall_http_io(const char *input, char *output, size_t* output_size, size_t max_output_size){

    CURL *curl;
    CURLcode res;
    std::stringstream out;

    printf("Untrusted OCALL HTTP I/O called with %s\n", input);

    if(!max_output_size) {
      sleep(1);
      printf("Untrusted OCALL HTTP I/O returns\n");
      return;
    }

    curl = curl_easy_init( );
    // TODO: If input is a json, do this:
    //json::JSON input_json = json::JSON::Load(input);
    //curl_easy_setopt( curl, CURLOPT_URL, input_json['url'].ToString().c_str() );
    curl_easy_setopt( curl, CURLOPT_URL, input );
    
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1); //Prevent "longjmp causes uninitialized stack frame" bug
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "deflate");
    //curl_easy_setopt(curl, CURLOPT_VERBOSE, true);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);
    
    res = curl_easy_perform( curl );
    if ( res != CURLE_OK ) {
        printf("CURL ERROR!\n");
    }

    curl_easy_cleanup(curl);

    std::string response = out.str();
    *output_size = response.length();

    if(response.length() < max_output_size){
        strcpy(output, response.c_str());
        printf(" -- returning %s\n", output);
    } else {
        printf("HTTP OCALL Error. Output size exceeds requested size.\n");
        //TODO: This can easily be handled by 2 OCALLs or better string handling. We omit this here.
        // Here, just put a json error object in the output
        std::string error = "{'error':'Output size exceeded'}";
        strcpy(output, error.c_str());
    }

}
