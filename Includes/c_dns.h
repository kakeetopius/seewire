#ifndef C_DNS_H
#define C_DNS_H

/*For the different types used in this header file*/
#include <stdint.h>
#include <sys/types.h>

/*---------------------DNS HEADER 12BYTES--------------------*/
struct dns_header {
  uint16_t transaction_id;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
};

#define DNS_HDR_LEN (sizeof(struct dns_header))

/*-------------------------QUERY TYPES-------------------*/
enum query_types {
  A = 1,
  NS = 2,
  CNAME = 5,
  SOA = 6,
  PTR = 12,
  MX = 15,
  TXT = 16,
  AAAA = 28,
  SRV = 33,
  CAA = 257,
  ANY = 255,
  HTTPS_RR = 65
};

/*---------------------QUERY CLASSES------------------------*/

enum query_class { 
    IN = 1, 
    CS = 2, 
    CH = 3, 
    HS = 4, 
    ANY_CLASS = 255 
};

void handle_dns(const u_char *packet, int msg_len);

void print_qtype(enum query_types type);

void print_qclass(enum query_class qclass);

const u_char *print_name(const u_char *start, const u_char *end, const u_char *name_ptr, int depth);

void handle_response(const u_char *message, int msg_len, struct dns_header *dns_hdr);

void handle_query(const u_char *message, int msg_len, struct dns_header *dns_hdr);

void handle_rdata(const u_char *data, enum query_types type, int len, const u_char *start, const u_char *end);

#endif
