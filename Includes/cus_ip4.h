#ifndef CUS_IP4_H
#define CUS_IP4_H

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ether.h>

#define IP_HEADER_LEN(i) ((i)->ip_hl * 4)


void handle_ip4(const u_char* packet, int msg_len);

#endif