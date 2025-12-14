#ifndef C_ARP_H
#define C_ARP_H

/*For ether_addr type*/
#include <netinet/ether.h>

/*For in_addr type*/
#include <arpa/inet.h>

#define ARP_HEADER_LEN (sizeof(struct arphdr))


/*-----------------------ARP HEADER FOR IPV4---------------------------------------*/
struct arp_ipv4 {
    struct ether_addr smac;
    struct in_addr sip;
    struct ether_addr dmac;
    struct in_addr dip;
}__attribute__ ((__packed__));

void handle_arp(const u_char* packet, int msg_len);
void handle_arp_request(const u_char* packet, int msg_len);
void handle_arp_reply(const u_char* packet, int msg_len);


#endif