#include <stdio.h>
#include "../Includes/cus_tcp.h"


void handle_tcp(const u_char* packet, int msg_len) {
    printf("|*-----------------------TCP-----------------------*|\n");
    struct tcphdr* tcp_header;  
    tcp_header = (struct tcphdr*)(packet);
    int tcplen = TCP_HEADER_LEN(tcp_header);

    printf("Header length:           %d bytes\n", tcplen);
    printf("Source Port:             %d\n", ntohs(tcp_header->source));
    printf("Destination Port:        %d\n",  ntohs(tcp_header->dest));
}