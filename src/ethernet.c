#include <stdio.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include "../Includes/c_ip4.h"
#include "../Includes/c_arp.h"
#include "../Includes/c_ether.h"


void handle_ethernet(const u_char* packet, int msg_len) {
    struct ether_header* ether_hdr; //ethernet header

    //printing out hardware info
    u_int8_t* ptr; 
    msg_len = msg_len - ETHER_HEADER_LEN;

    ether_hdr = (struct ether_header*) packet;
       
    int char_addr_len = ETHER_ADDR_LEN * 2 + 5 + 1; //each xcter plus 5 colons plus one null terminator 
    char src[char_addr_len];
    char dst[char_addr_len];

    ptr = ether_hdr->ether_shost;
    snprintf(src, char_addr_len, "%02x:%02x:%02x:%02x:%02x:%02x", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]); // 0 for padding 2 for max width
    ptr = ether_hdr->ether_dhost;
    snprintf(dst, char_addr_len, "%02x:%02x:%02x:%02x:%02x:%02x", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);

    printf("|*----------------------ETHER----------------------*|\n");
    printf("Source MAC:              %s\n", src);
    printf("Destination MAC:         %s\n", dst);
    
    if (msg_len <= 0) {
        printf("\n");
        return;
    }
    
    if (ntohs(ether_hdr->ether_type) == ETHERTYPE_IP) {
        handle_ip4(packet + ETHER_HEADER_LEN, msg_len);
    }
    else if (ntohs(ether_hdr->ether_type) == ETHERTYPE_ARP) {
        handle_arp(packet + ETHER_HEADER_LEN, msg_len);
    }
    else {
        printf("Captured unsupported packet\n");
        printf("Packet identifier: %x\n", ntohs(ether_hdr->ether_type));
        return;
    }
}   
