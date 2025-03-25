#ifndef CUS_ETHER_H
#define CUS_ETHER_H

#include <sys/types.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>


#define ETHER_HEADER_LEN (sizeof(struct ether_header))


void handle_ethernet(const u_char* packet, int msg_len);


#endif