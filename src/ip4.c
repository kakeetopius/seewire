#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include "../Includes/c_ip4.h"
#include "../Includes/c_tcp.h"
#include "../Includes/c_udp.h"


void handle_ip4(const u_char* packet, int msg_len) {
    struct ip* ip_header;          

    ip_header = (struct ip*)(packet);
    int iplen = IP_HEADER_LEN(ip_header);

    printf("|*----------------------IPv4----------------------*|\n");
    if (ip_header->ip_v != IPVERSION) {
        return;
    }

    //extracting the info
    char* srcip = inet_ntoa(ip_header->ip_src);

    printf("Header Length:           %d bytes\n", iplen);
    printf("Source IP:               %s\n", srcip);
    char* dstip = inet_ntoa(ip_header->ip_dst);
    printf("Destination IP:          %s\n", dstip);

    if (ip_header->ip_p == IPPROTO_TCP){
        handle_tcp(packet + iplen, msg_len - iplen);
    }
    else if (ip_header->ip_p == IPPROTO_UDP) {
        handle_udp(packet + iplen, msg_len - iplen);
    }
    else {
        printf("Unsupported protocol\n");
        printf("The protocol identifier is %d\n", ip_header->ip_p);
        return;
    }
}   