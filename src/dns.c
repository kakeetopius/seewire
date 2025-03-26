#include <netinet/in.h>
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

    const u_char* start = message;
    const u_char* end = message + msg_len;

    switch(rcode) {
        case 0: printf("0 No error\n"); break;
        case 1: printf("1 Format Error\n"); break;
        case 2: printf("2 Server Error\n"); break;
        case 3: printf("3 Non-Existent Domain\n"); break;
        case 4: printf("4 Not Implemented\n"); break;
        case 5: printf("5 Query Refused\n"); break;
        default:printf("Other Code %d", rcode); break;
    }

    uint16_t qdcount = ntohs(dns_hdr->qdcount);
    uint16_t ancount = ntohs(dns_hdr->ancount);

    const u_char* qd_end = NULL; /*to store final position after the names are printed*/

    /*printing out queries*/
    for(int i = 0; i < qdcount; i++) {
        printf("****Query %d****\n", i+1);
        printf("    Query Name           ");
        if (i == 0) {
            qd_end = print_name(start, end, start);
        }
        else if(i > 0 && qd_end != NULL) {
            qd_end = print_name(start, end, qd_end);
        } 
        printf("\n");
    }

    qd_end += 4; //by passing the qtype and qclass
    if (qd_end >= end) {
        return;
    }
    

    const u_char* rp_end = NULL; /*to store final position after responses*/
    for(int i = 0; i < ancount; i++) {
        printf("****Response %d****\n", i+1);
        printf("    Response For         ");
        if(i == 0) {
            rp_end = print_name(start, end, qd_end);
        }
        else if (i > 0 && rp_end != NULL) {
           rp_end = print_name(start, end, rp_end);
        }
        else{
            printf("End of Message\n");
        }
        printf("\n");
        
        /*Getting other fields of the answer section*/
        uint16_t type   = ntohs(*(uint16_t*) (rp_end));
        uint16_t qclass = ntohs(*(uint16_t*) (rp_end + 2));
        uint32_t ttl    = ntohl(*(uint32_t*) (rp_end + 4));
        uint16_t dlen   = ntohs(*(uint16_t*) (rp_end + 8));

        printf("    Query Type:          ");
        print_qtype(type);
        printf("    Query Class:         ");
        print_qclass(qclass);
        printf("    TTL:                 %d seconds\n", ttl);
        printf("    Data Len:            %d\n", dlen);

        rp_end = rp_end + 10 + dlen; 
    }
}

void handle_query(const u_char* message, int msg_len, struct dns_header* dns_hdr) {
    printf("|*----------------------DNSQR---------------------*|\n");

    const u_char* start = message;
    const u_char* end = message + msg_len;

    uint16_t qdcount = ntohs(dns_hdr->qdcount);
    
    const u_char* p = NULL; /*to store the final position after the QDs are printed*/

    for (int i = 0; i < qdcount; i++) {
        printf("****Query %d****\n", i+1);
        printf("    Query Name:          ");
        if (i == 0) {
            p = print_name(start, end, start);
        }
        else if (i > 0 && p != NULL) {
            p = print_name(p, end,p);
        }
        printf("\n");
    }

    if (p != NULL) {
        if (p + 4 <= end) {
            uint16_t* qtype = (uint16_t*) p; /*Getting two byte query type*/
            uint16_t Qtype = ntohs(*qtype);
            printf("    Query Type:          ");
            print_qtype(Qtype);
            uint16_t* qclass = (uint16_t*) (p+2);        /*Extracting the  QCLASS*/
            uint16_t Qclass = ntohs(*qclass);
            printf("    Query Class:         ");
            print_qclass(Qclass);
        }
    }
}

const u_char* print_name(const u_char* start, const u_char* end, const u_char* name_ptr) {
   
    if (name_ptr + 2 > end) { /* if the size is less than 2 bytes*/
        return NULL;
    }

    /*checking if the qname field is a pointer to another name*/
    if ((*name_ptr & 0xC0) == 0xC0) {
        int k = ((*name_ptr & 0x3F) << 8) + name_ptr[1]; /*Extracting the 14 bits for the offset*/   
        print_name(start, end, (start+k-12)); /*minus 12 to remove offset from start of header*/

        name_ptr+=2;    /*Position after the pointer for the very first call (before any recursion)*/

        return name_ptr; 
    }
    else {
        int len = *name_ptr; /*The length of the first word*/
    
        while(len != 0) {
            name_ptr++;         /*Moving pointer to first letter*/
            printf("%.*s", len, name_ptr);    
            name_ptr += len;   /*Moving the pointer to the next number*/
            len = *name_ptr;    /*Getting new length*/
            if(len != 0)
                printf("."); 

            if((len & 0xC0) == 0xC0) { /*---If there is a pointer in between---*/
                int k = ((len & 0x3F) << 8) + name_ptr[1]; 
                print_name(start, end, (start+k-12));
                break;
            }
        }      
              
        return ++name_ptr; /*Position after the last 0 of the very first call of this function*/     
     }

     /*----One of the trickiest I have had to endure wrriting. I'm sure i won't remember what anything in here means in 2 days.*/
}

void print_qtype(int type) {
    switch (type){
        case 1: printf("A"); break;
        case 2: printf("NS"); break;
        case 5: printf("CNAME"); break;
        case 6: printf("SOA"); break;
        case 12: printf("PTR"); break;
        case 15: printf("MX"); break;
        case 16: printf("TXT"); break;
        case 28: printf("AAAA"); break;
        case 33: printf("SRV"); break;
        case 257: printf("CAA"); break;
        case 255: printf("ANY"); break;
        case 65: printf("HTTPS RR"); break;
        default: printf("OTHER %d", type); break;
    }
    printf("\n");
}

void print_qclass(int qclass) {
    switch(qclass) {
        case 1: printf("IN"); break;
        case 2: printf("CS"); break;
        case 3: printf("CH"); break;
        case 4: printf("HS"); break;
        case 255: printf("ANY"); break;
        default: printf("OTHER %d", qclass); break;
    }
    printf("\n");
}