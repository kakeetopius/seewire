#include "net/datalink.h"
#include "net/arp.h"
#include "net/ip4.h"
#include "util/output_printer.h"

#include <net/ethernet.h>
#include <netinet/ether.h>
#include <stdio.h>

void handle_ethernet(const u_char *packet, int msg_len) {
    struct ether_header *ether_hdr; // ethernet header

    // printing out hardware info
    u_int8_t *ptr;
    msg_len = msg_len - ETHER_HEADER_LEN;

    ether_hdr = (struct ether_header *)packet;

    int char_addr_len = ETHER_ADDR_LEN * 2 + 5 + 1; // each xcter plus 5 colons plus one null terminator
    char src[char_addr_len];
    char dst[char_addr_len];

    ptr = ether_hdr->ether_shost;
    snprintf(src, char_addr_len, "%02x:%02x:%02x:%02x:%02x:%02x", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]); // 0 for padding 2 for max width
    ptr = ether_hdr->ether_dhost;
    snprintf(dst, char_addr_len, "%02x:%02x:%02x:%02x:%02x:%02x", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);

    print_protocol_header("ETHERNET");
    print_field("Source MAC:", src, STRING);
    print_field("Destination MAC:", dst, STRING);

    if (msg_len <= 0) {
	printf("\n");
	return;
    }

    if (ntohs(ether_hdr->ether_type) == ETHERTYPE_IP) {
	handle_ip4(packet + ETHER_HEADER_LEN, msg_len);
    } else if (ntohs(ether_hdr->ether_type) == ETHERTYPE_ARP) {
	handle_arp(packet + ETHER_HEADER_LEN, msg_len);
    } else {
	printf("Captured unsupported packet\n");
	printf("Packet identifier: %02x\n", ntohs(ether_hdr->ether_type));
	return;
    }
}

// Function handle_linuxsll is used to handle different formats that be encountered when capturing
// packets on virtual interfaces like loopback or when "any" interface option is used.
void handle_linuxsll(const u_char *packet, int pktlen) {
    struct sll_header *sll_hdr;
    sll_hdr = (struct sll_header *)packet;

    int hdr_len = datalink_header_len(DLT_LINUX_SLL);
    pktlen = pktlen - hdr_len;

    int upper_layer_proto = ntohs(sll_hdr->protocol_type);
    int link_layer_addr_type = ntohs(sll_hdr->hw_addr_type);
    int packet_type = ntohs(sll_hdr->packet_type);
    int hw_addr_len = ntohs(sll_hdr->hw_addr_len);

    print_protocol_header("LINUX COOKED PACKET");
    print_field("Packet type:", &packet_type, INTEGER);
    print_field("L2 Adress Type:", &link_layer_addr_type, INTEGER);
    print_field("L2 Address Len:", &hw_addr_len, INTEGER);

    if (link_layer_addr_type == ARPHRD_ETHER) {
	uint8_t *ptr = sll_hdr->hw_addr;
	char src[24];
	snprintf(src, 24, "%02x:%02x:%02x:%02x:%02x:%02x", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
	print_field("Source MAC:", src, STRING);
    }
    if (link_layer_addr_type == ARPHRD_LOOPBACK) {
	uint8_t *ptr = sll_hdr->hw_addr;
	char src[30];
	snprintf(src, 30, "%02x:%02x:%02x:%02x:%02x:%02x(loopback)", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
	print_field("Source MAC:", src, STRING);
    }
    if (upper_layer_proto == ETHERTYPE_IP) {
	handle_ip4(packet + hdr_len, pktlen);
    } else if (upper_layer_proto == ETHERTYPE_ARP) {
	handle_arp(packet + hdr_len, pktlen);
    } else {
	printf("Unsupported packet of type DLT_LINUX_SLL: %02x\n", upper_layer_proto);
	return;
    }
}

void handle_linuxsll2(const u_char *packet, int pktlen) {
    // upper layer protocol at offset 0 (upto 2).
    uint16_t upper_layer_proto = ntohs(*(uint16_t *)packet);

    int hdr_len = datalink_header_len(DLT_LINUX_SLL2);
    pktlen = pktlen - hdr_len;

    if (upper_layer_proto == ETHERTYPE_IP) {
	handle_ip4(packet + hdr_len, pktlen);
    } else if (upper_layer_proto == ETHERTYPE_ARP) {
	handle_arp(packet + hdr_len, pktlen);
    } else {
	printf("Unsupported packet of type DLT_LINUX_SLL2: %02x\n", upper_layer_proto);
	return;
    }
}

void handle_null_and_loop(const u_char *packet, int pktlen) {
    // upper layer protocol at offset 0 (upto 2). both are similar.
    uint16_t upper_layer_proto = ntohs(*(uint16_t *)packet);

    int hdr_len = datalink_header_len(DLT_LOOP);
    pktlen = pktlen - hdr_len;

    if (upper_layer_proto == AF_INET) {
	handle_ip4(packet + hdr_len, pktlen);
    } else {
	printf("Unsupported packet of type: DLT_LOOP: %02x\n", upper_layer_proto);
	return;
    }
}

void handle_datalink(const u_char *packet, int dlType, int packet_len) {
    switch (dlType) {
    case DLT_EN10MB:
	handle_ethernet(packet, packet_len);
	break;
    case DLT_LINUX_SLL:
	handle_linuxsll(packet, packet_len);
	break;
    case DLT_LINUX_SLL2:
	handle_linuxsll2(packet, packet_len);
	break;
    case DLT_NULL:
    case DLT_LOOP:
	handle_null_and_loop(packet, packet_len);
	break;
    default:
	printf("Unsupported datalink type: %d\n", dlType);
	return;
    }
}

int datalink_header_len(int dlt) {
    switch (dlt) {
    case DLT_EN10MB:
	return 14;
    case DLT_LINUX_SLL:
	return 16;
    case DLT_LINUX_SLL2:
	return 20;
    case DLT_NULL:
    case DLT_LOOP:
	return 4;
    default:
	return -1;
    }
}
