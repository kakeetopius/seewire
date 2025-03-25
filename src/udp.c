#include <stdio.h>
#include "../Includes/cus_udp.h"


void handle_udp(const u_char* packet, int msg_len) {
    printf("|*-----------------------UDP----------------------*|\n");
    struct udphdr* udp_header;
    udp_header = (struct udphdr*)(packet);
    int udplen = UDP_HEADER_LEN;
    int srcport, dstport;
    srcport =  ntohs(udp_header->source);
    dstport =  ntohs(udp_header->dest);

    printf("Header length:           %d bytes\n", udplen);
    printf("Source Port:             %d\n", srcport);
    printf("Destination Port:        %d\n", dstport);
}