#include <stdio.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include "../Includes/c_udp.h"
#include "../Includes/c_dns.h"

void handle_udp(const u_char* packet, int msg_len) {
    printf("|*-----------------------UDP----------------------*|\n");
    struct udphdr* udp_header;

    udp_header = (struct udphdr*)(packet);
    int udplen = UDP_HEADER_LEN;
    int srcport, dstport;

    msg_len = msg_len - udplen;

    srcport =  ntohs(udp_header->source);
    dstport =  ntohs(udp_header->dest);

    printf("Header length:           %d bytes\n", udplen);
    printf("Source Port:             %d\n", srcport);
    printf("Destination Port:        %d\n", dstport);
    
    if (msg_len <= 0) {
        printf("\n");
        return;
    }
    
    if(srcport == 53 || dstport == 53) {
        handle_dns(packet + udplen, msg_len);
    }
}

