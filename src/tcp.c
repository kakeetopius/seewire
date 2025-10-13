#include <stdio.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "../Includes/c_tcp.h"
#include "../Includes/c_http.h"

void handle_tcp(const u_char* packet, int msg_len) {
    printf("|*-----------------------TCP-----------------------*|\n");
    struct c_tcp_header* tcp_header = (struct c_tcp_header*) packet;
    int tcp_len = TCP_HEADER_LEN(tcp_header);
    msg_len = msg_len - tcp_len;

    int sport = ntohs(tcp_header->source_port);
    int dport = ntohs(tcp_header->dest_port);

    printf("Header length:           %d bytes\n", tcp_len);
    printf("Source Port:             %d\n", sport);
    printf("Destination Port:        %d\n", dport); 
    
    
    if (SYN_FLAG(tcp_header) && !ACK_FLAG(tcp_header)) {
        printf("##SYN PACKET##\n");
    }
    else if (SYN_FLAG(tcp_header) && ACK_FLAG(tcp_header)) {
        printf("##SYN-ACK PACKET##\n");
    }
    
    
    printf("Sequence No:             %u\n", ntohl(tcp_header->seq_num));
    printf("Acknowledgment No:       %u\n", ntohl(tcp_header->ack_num));
    printf("Payload Length:          %d\n", msg_len); 
    if (msg_len <= 0) {
        printf("\n");
        return;
    }
    
    if (sport == HTTP_TCP || dport == HTTP_TCP) {
        handle_http((packet + tcp_len), msg_len);    
    } 
}
