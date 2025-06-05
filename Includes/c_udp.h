#ifndef CUS_UDP_H
#define CUS_UDP_H

#include <sys/types.h>

#define UDP_HEADER_LEN (sizeof(struct udphdr)) 

void handle_udp(const u_char* packet, int msg_len);

enum udp_proto{
    UDPPROTO_DNS = 53,

};

#endif
