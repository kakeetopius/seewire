#include <arpa/inet.h>
#include <netinet/udp.h>
#include <stdio.h>

#include "net/dns.h"
#include "net/udp.h"
#include "util/output_printer.h"

// UDP Header (8 bytes)
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-------------------------------+-------------------------------+
// | Source Port (16 bits)         | Destination Port (16 bits)    |
// +-------------------------------+-------------------------------+
// | Length (16 bits)              | Checksum (16 bits)            |
// +-------------------------------+-------------------------------+
// | Data (variable)                                               |
// +---------------------------------------------------------------+
void handle_udp(const u_char *packet, int msg_len) {
    print_protocol_header("UDP");
    struct udphdr *udp_header;

    udp_header = (struct udphdr *)(packet);
    int udplen = UDP_HEADER_LEN;
    int srcport, dstport;

    msg_len = msg_len - udplen;

    srcport = ntohs(udp_header->source);
    dstport = ntohs(udp_header->dest);

    print_field("Header length:", &udplen, INTEGER);
    print_field("Source Port:", &srcport, INTEGER);
    print_field("Destination Port:", &dstport, INTEGER);

    if (msg_len <= 0) {
	printf("\n");
	return;
    }

    if (srcport == 53 || dstport == 53) {
	handle_dns(packet + udplen, msg_len);
    } else {
	printf("\n");
    }
}
