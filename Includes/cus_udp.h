#ifndef CUS_UDP_H
#define CUS_UDP_H

#include <netinet/udp.h>
#include <arpa/inet.h>

#define UDP_HEADER_LEN (sizeof(struct udphdr)) 

void handle_udp(const u_char* packet, int msg_len);
#endif