#include "../Includes/c_dns.h"
#include "../Includes/output_printer.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>

void handle_dns(const u_char *packet, int msg_len) {
     /*-----------if the payload is less than the size of the header.----------*/
     if (msg_len < 12) {
          return;
     }

    print_protocol_header("DNS");
     /*-----------Dns header-------------------*/
     struct dns_header *dns_hdr = (struct dns_header *)packet;

     /*-------------Converting header to host byte order--------------*/
     uint16_t trans_id = ntohs(dns_hdr->transaction_id);
     uint16_t flags = ntohs(dns_hdr->flags);

     /*--------------Extracting flag fields--------------------------*/
     uint8_t qr = (flags >> 15) & 0x01;     // Extracting the type of message(Query / Response)
     uint8_t opcode = (flags >> 11) & 0x0F; // 4-bit Opcode
     uint8_t aa = (flags >> 10) & 0x01;     // 1-bit Authoritative Answer
     uint8_t tc = (flags >> 9) & 0x01;      // 1-bit Truncated
     uint8_t rd = (flags >> 8) & 0x01;      // 1-bit Recursion Desired
     uint8_t ra = (flags >> 7) & 0x01;      // 1-bit Recursion Available

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
          handle_query(packet + DNS_HDR_LEN, msg_len - DNS_HDR_LEN, dns_hdr);
     else if (qr == 1)
          handle_response(packet + DNS_HDR_LEN, msg_len - DNS_HDR_LEN, dns_hdr);
}

void handle_query(const u_char *message, int msg_len, struct dns_header *dns_hdr) {
     printf("|*----------------------DNSQR---------------------*|\n");

     const u_char *start = message;
     const u_char *end = message + msg_len;

     uint16_t qdcount = ntohs(dns_hdr->qdcount);

     const u_char *p = NULL; /*to store the final position after the QDs are printed*/

     for (int i = 0; i < qdcount; i++) {
          printf("****Query %d****\n", i + 1);
          printf("    Query Name:          ");
          if (i == 0) {
               p = print_name(start, end, start, 0);
          } else if (i > 0 && p != NULL) {
               p = print_name(p, end, p, 0);
          }
          printf("\n");
     }

     if (p != NULL) {
          if (p + 4 <= end) {
               uint16_t *qtype = (uint16_t *)p; /*Getting two byte query type*/
               uint16_t Qtype = ntohs(*qtype);
               printf("    Query Type:          ");
               print_qtype(Qtype);
               uint16_t *qclass = (uint16_t *)(p + 2); /*Extracting the  QCLASS*/
               uint16_t Qclass = ntohs(*qclass);
               printf("    Query Class:         ");
               print_qclass(Qclass);
          }
     }
     printf("\n");
}

void handle_response(const u_char *message, int msg_len, struct dns_header *dns_hdr) {
     printf("|*----------------------DNSRR---------------------*|\n");
     uint16_t flags = ntohs(dns_hdr->flags);
     uint8_t rcode = flags & 0x0F; // 4-bit Response Code
     printf("Response Code:           ");

     const u_char *start = message; /*To help with domain name printing*/
     const u_char *end = message + msg_len;

     switch (rcode) {
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

     uint16_t qdcount = ntohs(dns_hdr->qdcount);
     uint16_t ancount = ntohs(dns_hdr->ancount);

     const u_char *qd_end = NULL; /*to store final position after the names are printed*/

     /*printing out queries in response*/
     for (int i = 0; i < qdcount; i++) {
          printf("****Query %d****\n", i + 1);
          printf("    Query Name           ");
          if (i == 0) {
               qd_end = print_name(start, end, start, 0);
          } else if (i > 0 && qd_end != NULL) {
               qd_end = print_name(start, end, qd_end, 0);
          }
          printf("\n");
     }

     qd_end += 4; // by passing the qtype and qclass
     if (qd_end > end) {
          return;
     }

     const u_char *rp_end = NULL; /*to store final position after responses*/
     for (int i = 0; i < ancount; i++) {
          printf("****Response %d****\n", i + 1);
          printf("    Response For         ");
          if (i == 0) {
               rp_end = print_name(start, end, qd_end, 0);
          } else if (i > 0 && rp_end != NULL) {
               rp_end = print_name(start, end, rp_end, 0);
          } else {
               printf("End of Message\n");
          }
          printf("\n");

          /*Getting other fields of the answer section*/
          uint16_t type = ntohs(*(uint16_t *)(rp_end));
          uint16_t qclass = ntohs(*(uint16_t *)(rp_end + 2));
          uint32_t ttl = ntohl(*(uint32_t *)(rp_end + 4));
          uint16_t dlen = ntohs(*(uint16_t *)(rp_end + 8));
          const u_char *rdata = (rp_end + 10);

          printf("    Query Type:          ");
          print_qtype(type);
          printf("    Query Class:         ");
          print_qclass(qclass);
          printf("    TTL:                 %d seconds\n", ttl);
          printf("    Data Len:            %d\n", dlen);

          handle_rdata(rdata, type, dlen, start, end);

          rp_end = rp_end + 10 + dlen; // correcting rp_end to point to next response
     }
     printf("\n");
}

void handle_rdata(const u_char *data, enum query_types type, int len, const u_char *start, const u_char *end) {
     /*Start is included to help in printing the domain name in cname*/
     if ((data + len) > end) {
          return;
     }

     printf("    Record:              ");
     if (type == A) {
          struct in_addr *ipaddr = (struct in_addr *)data;
          char ipaddr_str[INET_ADDRSTRLEN];
          inet_ntop(AF_INET, ipaddr, ipaddr_str, INET_ADDRSTRLEN);
          printf("%s", ipaddr_str);
     } else if (type == AAAA) {
          struct in6_addr *ipaddr = (struct in6_addr *)data;
          char ipaddr6_str[INET6_ADDRSTRLEN];
          inet_ntop(AF_INET6, ipaddr, ipaddr6_str, INET6_ADDRSTRLEN);
          printf("%s", ipaddr6_str);
     } else if (type == CNAME) {
          print_name(start, end, data, 0);
     } else if (type == MX) {
          uint16_t preference = ntohs(*(uint16_t *)(data));
          const u_char *mail = (data + 2); /*Plus two to jump preference*/
          print_name(start, end, mail, 0);
          printf(" (Pref %d)", preference);
     } else if (type == TXT) {
          uint8_t len = *(uint8_t *)(data);
          const u_char *txt = (data + 1);
          printf("%.*s", len, txt);
     } else if (type == NS) {
          print_name(start, end, data, 0);
     }
     printf("\n");
}

const u_char *print_name(const u_char *start, const u_char *end, const u_char *name_ptr, int depth) {
     /*Explanation of the paramaters (for me when i forget later)*/
     /*
         start---- The beginning of the dns message(qdata) after the dns header. ie exactly 12 bytes from the beginning of entire dns message
         end------ The end of the entire dns packet to prevent overflow
         name_ptr--A pointer to where the name is suspected to be within the message.
         depth-----Help to prevent infinite recursion, just in case.
     */
     /*Returns the start of the next query or response*/

     /*Prevents infinite recursion*/
     if (depth > 10) {
          printf(" [Error: Too many compression pointers]\n");
          return NULL;
     }

     /* if the size left is less than 2 bytes*/
     if (name_ptr + 2 > end) {
          return NULL;
     }

     /*checking if the qname field is a pointer to another name*/
     if ((*name_ptr & 0xC0) == 0xC0) {
          int k = ((*name_ptr & 0x3F) << 8) + name_ptr[1]; /*Extracting the 14 bits for the offset*/
          k -= 12;                                         /*Minus 12 to skip header*/

          print_name(start, end, (start + k), depth + 1);

          name_ptr += 2; /*Position after the pointer for the very first call (before any recursion)*/

          return name_ptr;
     } else {
          int len = *name_ptr; /*The length of the first word*/

          while (len != 0) {
               name_ptr++; /*Moving pointer to first letter*/
               fprintf(stdout, "%.*s", len, name_ptr);
               name_ptr += len; /*Moving the pointer to the next number ie length of the next word*/
               len = *name_ptr; /*Getting the new word length*/
               if (len != 0)    /*if not at the end yet put a dot*/
                    fprintf(stdout, ".");

               if ((len & 0xC0) == 0xC0) { /*---If there is a pointer to another name in between somewhere instead of a length---*/
                    int k = ((len & 0x3F) << 8) + name_ptr[1];
                    print_name(start, end, (start + k - 12), depth + 1);
                    break; /*because a pointer in the middle shows no other word here. They are somewhere else hence break*/
               }
          }

          return ++name_ptr; /*Returning the position after the last '0' of the qdata/resp of  the very first call of this function before any recursion.
                                 ie returning the position after the qdata/resp
                             */
     }
}

void print_qtype(enum query_types type) {
     switch (type) {
     case A:
          printf("A");
          break;
     case NS:
          printf("NS");
          break;
     case CNAME:
          printf("CNAME");
          break;
     case SOA:
          printf("SOA");
          break;
     case PTR:
          printf("PTR");
          break;
     case MX:
          printf("MX");
          break;
     case TXT:
          printf("TXT");
          break;
     case AAAA:
          printf("AAAA");
          break;
     case SRV:
          printf("SRV");
          break;
     case CAA:
          printf("CAA");
          break;
     case ANY:
          printf("ANY");
          break;
     case HTTPS_RR:
          printf("HTTPS RR");
          break;
     default:
          printf("OTHER %d", type);
          break;
     }
     printf("\n");
}

void print_qclass(enum query_class qclass) {
     switch (qclass) {
     case IN:
          printf("IN");
          break;
     case CS:
          printf("CS");
          break;
     case CH:
          printf("CH");
          break;
     case HS:
          printf("HS");
          break;
     case ANY_CLASS:
          printf("ANY");
          break;
     default:
          printf("OTHER %d", qclass);
          break;
     }
     printf("\n");
}
