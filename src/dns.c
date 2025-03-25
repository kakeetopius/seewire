#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include "../Includes/cus_dns.h"

void handle_dns(const u_char* packet, int msg_len) {
    /*-----------if the payload is less than the size of the header.----------*/
    if (msg_len < 12) {
        return;
    }

    printf("|*-----------------------DNS----------------------*|\n");

    /*-----------Dns header-------------------*/
    struct dns_header* dns_hdr = (struct dns_header*) packet;
    
    /*-------------Converting header to host byte order--------------*/
    uint16_t trans_id = ntohs(dns_hdr->transaction_id);
    uint16_t flags = ntohs(dns_hdr->flags);
 
    /*--------------Extracting flag fields--------------------------*/
    uint8_t qr = (flags >> 15) & 0x01;      // Extracting the type of message(Query / Response)
    uint8_t opcode = (flags >> 11) & 0x0F;  // 4-bit Opcode
    uint8_t aa = (flags >> 10) & 0x01;      // 1-bit Authoritative Answer
    uint8_t tc = (flags >> 9) & 0x01;       // 1-bit Truncated
    uint8_t rd = (flags >> 8) & 0x01;       // 1-bit Recursion Desired
    uint8_t ra = (flags >> 7) & 0x01;       // 1-bit Recursion Available
    

    /*----------------Printing out header info---------------------------*/
    printf("Transaction ID:          %d\n", trans_id);
    printf("QR:                      %d %s\n", qr, qr == 0 ? "Query" : "Response");
    printf("Opcode:                  %d %s\n", opcode, opcode == 0 ? "Standard" : "Non Standard\n");
    printf("Authoritative Answer:    %d\n", aa);
    printf("Truncated:               %d\n", tc); 
    printf("RA:                      %d %s\n", ra, ra == 1 ? "recursion available" : "");
    printf("RD:                      %d %s\n", rd, rd == 1 ? "recursion desired" : "");
    printf("QDCOUNT:                 %d\n", ntohs(dns_hdr->qdcount));
    printf("ANCOUNT:                 %d\n", ntohs(dns_hdr->ancount));
    printf("NSCOUNT:                 %d\n", ntohs(dns_hdr->nscount));
    printf("ARCOUNT:                 %d\n", ntohs(dns_hdr->arcount));

    if (qr == 0) 
        handle_query(packet+DNS_HDR_LEN, msg_len-DNS_HDR_LEN, dns_hdr);
    else if (qr == 1)
        handle_response(packet+DNS_HDR_LEN, msg_len-DNS_HDR_LEN, dns_hdr);
}

void handle_response(const u_char* message, int msg_len, struct dns_header* dns_hdr) {
    printf("|*----------------------DNSRR---------------------*|\n");
    uint16_t flags = ntohs(dns_hdr->flags);
    uint8_t rcode = flags & 0x0F;           // 4-bit Response Code
    printf("Response Code:           ");

    switch(rcode) {
        case 0:
            printf("0 No error\n");
            break;
        case 1:
            printf("1 Format Error\n");
            break;
        case 2:
            printf("2 Server Error\n");
            break;
        case 3: 
            printf("3 Non-Existent Domain\n");
            break;
        case 4:
            printf("4 Not Implemented\n");
            break;
        case 5:
            printf("5 Query Refused\n");
            break;
        default:
            printf("Other Code %d", rcode);
            break;
    }


}

void handle_query(const u_char* message, int msg_len, struct dns_header* dns_hdr) {
    printf("|*----------------------DNSQR---------------------*|\n");

    const u_char* start = message;
    const u_char* end = message + msg_len;

    uint16_t qdcount = ntohs(dns_hdr->qdcount);
    
    if (qdcount != 0) {
        printf("Query %d\n", qdcount);
        print_name(start, end, start);
        printf("\n");
    }
}

char* print_name(const u_char* start, const u_char* end, const u_char* name_ptr) {
    if (name_ptr + 2 > end) { /* if the size is less than 2 bytes*/
        
    }

    /*checking if the qname field is a pointer to another name*/
    if ((*name_ptr & 0xC0) == 0xC0) {

        int k = ((*name_ptr & 0x3F) << 8) + name_ptr[1]; /*Extracting the 14 bits for the offset*/

        print_name(start, end, start+k);
    }
    else {
        int len = *name_ptr; /*The length of the first word*/
        name_ptr++;                               /*Moving pointer to first letter*/

        if (name_ptr + len + 1 > end) {
            
        }
            
        printf("%.*s", len, name_ptr);     /*printing the word with width of len*/
        name_ptr = name_ptr + len;                 /*Moving the pointer to the next number*/
        
        if(*name_ptr != 0) {
            printf(".");
            print_name(start, end, name_ptr);
        }
    }
}   