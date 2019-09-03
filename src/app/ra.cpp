#include "la_dh.h"
#include "ra.h"
#include "enclave_u.h"
#include "logger.h"
#include "sgx_errors.h"

#include "TcpConnection.h"

#include "nrt_ra.h"

static int ra_send_message_to( remote_enclave_t dest, ra_socket_t* ra_socket,
                            nrt_ra_request_header_t* msg,
                            boost::asio::io_service* ios ) {
    message_t net_msg;
    boost::system::error_code err;
    tcp::resolver resolver(*ios);
    tcp::resolver::query query(dest.ip, dest.port);
    tcp::resolver::iterator iter = resolver.resolve(query);

    ra_socket->conn = network::TcpConnection::create(*ios);

    boost::asio::connect(ra_socket->conn->socket(), iter, err);
    if( err ) {
      return -1;
    }

    memset( &net_msg, 0, sizeof(net_msg) );

    net_msg.type = NETWORK_RA_MESSAGE_QUOTE;
    net_msg.data_plaintext = (void*) msg;
    // The size of the body + ra_type(1 bytes) + size field(4) + align
    net_msg.size_plaintext = msg->size + 8;
    err = ra_socket->conn->send_message( &net_msg );
    if( err != 0 ) return -1;
    return 0;
}

int ra_send_quote_to( sgx_enclave_id_t eid, const char* destination_ip, const char* destination_port,
                   ra_socket_t* ra_socket, boost::asio::io_service *ios ) {
    sgx_status_t ret;
    int status;
    nrt_ra_request_header_t *p_msg_quote = NULL;
    remote_enclave_t destination;
    strcpy( destination.ip,  destination_ip );
    strcpy( destination.port, destination_port );

    ret = ecall_enclave_init_ra( eid, &status, true, &(ra_socket->context) );
    if( ret != SGX_SUCCESS ) {
        print_error_message(ret);
        return ret;
    }
    if( status != SGX_SUCCESS ) {
        print_error_message((sgx_status_t)status);
        return status;
    }

    ret = nrt_ra_get_msg_quote( eid, ra_socket->context, &p_msg_quote );
    if( ret != SGX_SUCCESS ) {
        return ret;
    }
    if( status != SGX_SUCCESS ) {
        return ret;
    }

    status = ra_send_message_to( destination, ra_socket, p_msg_quote, ios );
    if( status != 0 ) {
        free(p_msg_quote);
        return -1;
    }

    free(p_msg_quote);
    return ret;
}

int ra_verify_quote( quote_t* quote ) {
    return 0;
}

int ra_close() {
    return -1;
}
