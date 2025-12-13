#include <stdio.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "../Includes/c_tcp.h"
#include "../Includes/c_http.h"
#include "../Includes/output_printer.h"

void handle_tcp(const u_char* packet, int msg_len) {
    print_protocol_header("TCP"); 
    struct c_tcp_header* tcp_header = (struct c_tcp_header*) packet;
    int tcp_len = TCP_HEADER_LEN(tcp_header);
    msg_len = msg_len - tcp_len;

    int sport = ntohs(tcp_header->source_port);
    int dport = ntohs(tcp_header->dest_port);

    print_field("Header length", &tcp_len, INTEGER);
    print_field("Source Port:", &sport, INTEGER);
    print_field("Destination Port:", &dport, INTEGER); 
    
    
    if (SYN_FLAG(tcp_header) && !ACK_FLAG(tcp_header)) {
        printf("##SYN PACKET##\n");
    }
    else if (SYN_FLAG(tcp_header) && ACK_FLAG(tcp_header)) {
        printf("##SYN-ACK PACKET##\n");
    }
    
    uint32_t seq = ntohl(tcp_header->seq_num); 
    uint32_t ack = ntohl(tcp_header->ack_num);
    print_field("Sequence No:", &seq, INTEGER);
    print_field("Acknowledgment No:", &ack, INTEGER);
    print_field("Payload Length:", &msg_len, INTEGER); 

    if (msg_len <= 0) {
        printf("\n");
        return;
    }
    
    if (sport == HTTP_TCP || dport == HTTP_TCP) {
        handle_http((packet + tcp_len), msg_len);    
    } 
    else {
	printf("\n");
    }
}
