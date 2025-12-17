#include <arpa/inet.h>
#include <netinet/ip.h>
#include <stdio.h>

#include "net/ip4.h"
#include "net/tcp.h"
#include "net/udp.h"
#include "util/output_printer.h"

// IPv4 Header (minimum 20 bytes)
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-------------------------------+-------------------------------+
// | Version (4) | IHL (4) | Type of Service (8) | Total Length (16) |
// +-------------------------------+-------------------------------+
// | Identification (16) | Flags (3) | Fragment Offset (13)         |
// +-------------------------------+-------------------------------+
// | Time to Live (8) | Protocol (8) | Header Checksum (16)        |
// +-------------------------------+-------------------------------+
// | Source IP Address (32 bits)                                      |
// +---------------------------------------------------------------+
// | Destination IP Address (32 bits)                                 |
// +---------------------------------------------------------------+
// | Options (variable, if IHL > 5)                                   |
// +---------------------------------------------------------------+
// | Data (variable)                                                  |
// +---------------------------------------------------------------+
void handle_ip4(const u_char *packet, int msg_len) {
    struct ip *ip_header;

    ip_header = (struct ip *)(packet);
    int iplen = IP_HEADER_LEN(ip_header);
    msg_len = msg_len - iplen;

    print_protocol_header("IPv4");
    if (ip_header->ip_v != IPVERSION) {
	return;
    }

    // extracting the info
    char *srcip = inet_ntoa(ip_header->ip_src);

    print_field("Header Length:", &iplen, INTEGER);
    print_field("Source IP:", srcip, STRING);
    char *dstip = inet_ntoa(ip_header->ip_dst);
    print_field("Destination IP:", dstip, STRING);

    if (msg_len <= 0) {
	printf("\n");
	return;
    }

    if (ip_header->ip_p == IPPROTO_TCP) {
	handle_tcp(packet + iplen, msg_len);
    } else if (ip_header->ip_p == IPPROTO_UDP) {
	handle_udp(packet + iplen, msg_len);
    } else {
	printf("Unsupported protocol\n");
	printf("The protocol identifier is %d\n", ip_header->ip_p);
	return;
    }
}
