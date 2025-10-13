#ifndef C_ETHER_H
#define C_ETHER_H

/*For the u_char type*/
#include <sys/types.h>


#define ETHER_HEADER_LEN (sizeof(struct ether_header))


void handle_ethernet(const u_char* packet, int msg_len);


#endif