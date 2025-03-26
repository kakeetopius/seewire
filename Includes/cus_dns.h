#ifndef CUS_DNS_H
#define CUS_DNS_H

#include <stdint.h>
#include <sys/types.h>
#include <arpa/inet.h>

/*--------------------------DNS HEADER 12BYTES------------------------------------*/
struct dns_header {
    uint16_t transaction_id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

#define DNS_HDR_LEN (sizeof(struct dns_header))


void handle_dns(const u_char* packet, int msg_len);

void print_qtype(int type);

void print_qclass(int qclass);

const u_char* print_name(const u_char* start, const u_char* end, const u_char* name_ptr);

void handle_response(const u_char* message, int msg_len, struct dns_header* dns_hdr);

void handle_query(const u_char* message, int msg_len, struct dns_header* dns_hdr);

#endif
