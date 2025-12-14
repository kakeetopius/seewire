#ifndef DATALINK_H
#define DATALINK_H

/*For the u_char type*/
#include <sys/types.h>
// for the uint16_t type.
#include <pcap.h>

#define ETHER_HEADER_LEN (sizeof(struct ether_header))

struct sll_header {
    uint16_t packet_type;
    uint16_t hw_addr_type;
    uint16_t hw_addr_len;
    uint8_t hw_addr[8];
    uint16_t protocol_type;
};

void handle_ethernet(const u_char *packet, int msg_len);
void handle_datalink(const u_char *packet, int dl_type, int packet_len);
int datalink_header_len(int dlt);

#endif
