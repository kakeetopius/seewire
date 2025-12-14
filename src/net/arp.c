#include "net/arp.h"
#include "util/output_printer.h"
#include <stdio.h>

void handle_arp(const u_char *packet, int msg_len) {
    struct arphdr *arp_header = (struct arphdr *)packet;

    if (ntohs(arp_header->ar_hrd) != ARPHRD_ETHER)
	return;
    else if (ntohs(arp_header->ar_pro) != ETHERTYPE_IP)
	return;

    if (ntohs(arp_header->ar_op) == ARPOP_REQUEST)
	handle_arp_request(packet + ARP_HEADER_LEN, msg_len - ARP_HEADER_LEN);
    else if (ntohs(arp_header->ar_op) == ARPOP_REPLY)
	handle_arp_reply(packet + ARP_HEADER_LEN, msg_len - ARP_HEADER_LEN);
}

void handle_arp_request(const u_char *packet, int msg_len) {
    print_protocol_header("ARP_REQUEST");
    struct arp_ipv4 *arp_data = (struct arp_ipv4 *)packet;

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(arp_data->sip), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(arp_data->dip), dst_ip, INET_ADDRSTRLEN);

    char *src_mac = ether_ntoa(&arp_data->smac);

    print_field("Who is:", dst_ip, STRING);
    print_field("Says:", src_ip, STRING);
    if (src_mac)
	print_field("Tell:", src_mac, STRING);
    printf("\n");
}

void handle_arp_reply(const u_char *packet, int msg_len) {
    print_protocol_header("ARP_REPLY");
    struct arp_ipv4 *arp_data = (struct arp_ipv4 *)packet;

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(arp_data->sip), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(arp_data->dip), dst_ip, INET_ADDRSTRLEN);

    char *src_mac = ether_ntoa(&arp_data->smac);
    char *dst_mac = ether_ntoa(&(arp_data->dmac));

    if (src_mac)
	print_field("Source MAC:", src_mac, STRING);
    print_field("Is At:", src_ip, STRING);
    if (dst_mac)
	print_field("Destination MAC:", dst_mac, STRING);
    print_field("Destination IP:", dst_ip, STRING);
    printf("\n");
}
