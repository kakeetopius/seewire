#ifndef C_TCP_H
#define C_TCP_H

#define TCP_HEADER_LEN(i) ((i)->doff * 4)

#include <sys/types.h>

enum tcp_proto {
    TCPPROTO_HTTP = 80,
    TCPPROTO_HTTPS = 443,
};

void handle_tcp(const u_char* packet, int msg_len);

#endif
