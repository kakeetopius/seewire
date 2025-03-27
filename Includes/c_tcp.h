#ifndef C_TCP_H
#define C_TCP_H

#define TCP_HEADER_LEN(i) ((i)->doff * 4)

#include <sys/types.h>


void handle_tcp(const u_char* packet, int msg_len);

#endif