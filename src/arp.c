#include <stdio.h>
#include "../Includes/c_arp.h"



void handle_arp(const u_char* packet, int msg_len) {
    struct arphdr* arp_header = (struct arphdr*)packet;

    if(ntohs(arp_header->ar_hrd) != ARPHRD_ETHER)
        return;
    else if (ntohs(arp_header->ar_pro) != ETHERTYPE_IP) 
        return;

    if (ntohs(arp_header->ar_op) == ARPOP_REQUEST) 
        handle_arp_request(packet + ARP_HEADER_LEN, msg_len - ARP_HEADER_LEN);
    else if(ntohs(arp_header->ar_op) == ARPOP_REPLY) 
        handle_arp_reply(packet + ARP_HEADER_LEN, msg_len - ARP_HEADER_LEN);
}


void handle_arp_request(const u_char* packet, int msg_len) {
    printf("|*------------------ARP REQUEST-------------------*|\n");
    struct arp_ipv4* arp_data = (struct arp_ipv4*) packet;

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(arp_data->sip), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(arp_data->dip), dst_ip, INET_ADDRSTRLEN);

    char* src_mac = ether_ntoa(&arp_data->smac);

    printf("Who is:                  %s\n", dst_ip);
    printf("Says:                    %s\n", src_ip);
    printf("Tell:                    %s\n", src_mac);
}



void handle_arp_reply(const u_char* packet, int msg_len) {
    printf("|*-------------------ARP REPLY--------------------*|\n");
    struct arp_ipv4* arp_data = (struct arp_ipv4*) packet;

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(arp_data->sip), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(arp_data->dip), dst_ip, INET_ADDRSTRLEN);
    
    char* src_mac = ether_ntoa(&arp_data->smac);

    printf("Source MAC:              %s\n", src_mac);
    printf("Is At:                   %s\n", src_ip);
    char* dst_mac = ether_ntoa(&(arp_data->dmac));
    printf("Destination MAC:         %s\n", dst_mac);
    printf("Destination IP:          %s\n", dst_ip);
}