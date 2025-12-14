#ifndef IP4_H
#define IP4_H

/*For the u_char type*/
#include <sys/types.h>

#define IP_HEADER_LEN(i) ((i)->ip_hl * 4)

void handle_ip4(const u_char *packet, int msg_len);

#endif
