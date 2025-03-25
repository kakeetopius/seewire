#ifndef CUS_TCP_H
#define CUS_TCP_H

#define TCP_HEADER_LEN(i) ((i)->doff * 4)

#include <netinet/tcp.h>
#include <arpa/inet.h>


void handle_tcp(const u_char* packet, int msg_len);

#endif