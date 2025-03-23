#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

#include "../Includes/list.h"


#define ETHER_HEADER_LEN (sizeof(struct ether_header))
#define IP_HEADER_LEN(i) ((i)->ip_hl * 4)
#define TCP_HEADER_LEN(i) ((i)->doff * 4)
#define UDP_HEADER_LEN (sizeof(struct udphdr)) 


void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
void handle_ethernet(const u_char* packet);
void handle_ip4(const u_char* packet);
void handle_tcp(const u_char* packet);
void handle_udp(const u_char* packet);

int status;
char errbuff[PCAP_ERRBUF_SIZE];


int main(int argc, char** argv) {

    char* error_message = "Usage: ./capture <interface> -a to capture all packets.\nUsage: ./capture <interface> -f <filter> to filter the packets\nUse flag -p to set promiscous mode\n";
    List lst = createList();
    printList(lst);
    //--arg indicators--
    int a = 0;
    int f = 0;
    int p = 0;

    if (argc < 3) {
        printf("%s", error_message);
        return -5;
    }

    //===========================handling inputed filters=================================
    char flag;                // for flag arguments
    int f_pos;               // for position of the -f
    char* interface = argv[1];
    char filter[50] = "";   //for the filter entered.
    int num_args = 2;       //total arguments without filter words; 2 for the program name and the interface.

    //---Checking for flags---
    for (int i = 2; i < argc; i++) {
        if (*(argv[i]) == '-') {
            flag = *(argv[i] + 1);
            switch(flag) {
                case 'p':
                    p = 1;
                    num_args++;
                    break;
                case 'a':
                    a = 1;
                    num_args++;
                    break;
                case 'f':
                    f = 1;
                    f_pos = i; // taking note of position of the -f argument.
                    num_args++;
                    break;
                default:
                    printf("Unknown argument: %c\n", flag);
                    return -1;    
            }
        }
    }

    // Checking options set.
    if (a == 1 && f == 1) {
        printf("Cannot set both -a and -f\n");
        printf("%s\n", error_message);
        return -1;
    }
    else if (a == 1) {
        printf("Option: Capture all packets\n");
    }
    else if (f == 1) {
        int num_filter_words = argc - num_args;     //minus the rest of arguments

        if (num_filter_words == 0) {
            printf("No filters entered\n");
            printf("%s", error_message);
            return -6;
        }   
       
        int filter_length = 0;
        //----Determing the length of the filter entered.-------
        //----i for checking argv; j for controlling the loop.----
        for (int i = f_pos + 1, j = 0; j < num_filter_words; i++,j++) {
           filter_length = filter_length + strlen(argv[i]) + 1;   // plus one of space between and null terminator for last
        }   
        if (filter_length > 50) {
            printf("Filter too long\n");
            return -8;
        }
        
        //------Appending the filter to the filter buffer with space between arguments
        for (int i = f_pos + 1, j = 0; j < num_filter_words; i++,j++) {
            strcat(filter, argv[i]);
            strcat(filter, " ");
        }
        
        printf("Filter entered is: %s\n", filter);
    }
    else {
        printf("%s", error_message);
        return -4;
    }
    

    status = pcap_init(0, errbuff);
    if (status != 0) {
        printf("Error: %s\n", pcap_strerror(status));
        return -1;
    }

    pcap_t* handle = pcap_create(interface, errbuff);
    if (handle == NULL) {
        pcap_perror(handle, "Error ");
    }

    //setting length
    pcap_set_snaplen(handle, 65535);
    
    //setting promiscous mode.
    if (p == 1) {
        status = pcap_set_promisc(handle, 1);
        if (status != 0) {
            pcap_perror(handle, "Error set promiscous mode ");
        }
    
        if (*interface == 'w') {
            pcap_set_rfmon(handle, 1);
        }  
    }
    
    
    status = pcap_activate(handle);
    if (status != 0) {
        pcap_perror(handle, "Error Activating ");
        return -9;
    }

    //setting direction
    status = pcap_setdirection(handle, PCAP_D_INOUT);
    if (status != 0) {
        pcap_perror(handle, "Error Setting Direction ");
        return -4;
    }

    struct bpf_program bp_filter;
    //setting filter
    if (f == 1) {
        status = pcap_compile(handle, &bp_filter, filter, 1, PCAP_NETMASK_UNKNOWN);  
        if (status != 0) {
            pcap_perror(handle, "Error BPF ");
            return -2;
        }
        status = pcap_setfilter(handle, &bp_filter);
        if (status != 0) {
            pcap_perror(handle, "Error Activating filter \n");
            return -2;
        }
        printf("Filtering packets.....\n");
    }

    //capture packets in an infinite loop.
    pcap_loop(handle, -1, callback, NULL);
    pcap_freecode(&bp_filter);
    pcap_close(handle);
   
    return 0;
}


void callback(u_char *user, const struct pcap_pkthdr* hdr, const u_char *packet_data) {
    static unsigned long packet_count = 1;
    printf("--------------------------------------------------------------------------------------------------\n");
    printf("Captured packet\nTotal Packet Length: %d\n", hdr->len);
    printf("Packet Count: %lu\n", packet_count);

    handle_ethernet(packet_data);
    
    packet_count++;
}


void handle_ethernet(const u_char* packet) {
    struct ether_header* ether_hdr; //ethernet header

    //printing out hardware info
    u_int8_t* ptr; 

    ether_hdr = (struct ether_header*) packet;

    //begginning with source hardware address.
    ptr = ether_hdr->ether_shost;
    int i = ETHER_ADDR_LEN;
    
    printf("================ETHER================\n");
    printf("Source Address: ");
    while(i > 0) {
        if (i == ETHER_ADDR_LEN) {
            printf(" "); //to prevent starting with colon
        }
        else {
            printf(":");
        }
        printf("%x", *ptr);
        ptr++;
        i--;
    }

    ptr = ether_hdr->ether_dhost;
    i = ETHER_ADDR_LEN;
    printf("\nDestination Address: ");
    while(i > 0) {
        if (i == ETHER_ADDR_LEN) {
            printf(" "); 
        }
        else {
            printf(":");
        }
        printf("%x", *ptr);
        ptr++;
        i--;
    }
    printf("\n");

    if (ntohs(ether_hdr->ether_type) == ETHERTYPE_IP) {
        printf("Captured an IP packet\n");
        handle_ip4(packet + ETHER_HEADER_LEN);
    }
    else if (ntohs(ether_hdr->ether_type) == ETHERTYPE_ARP) {
        printf("Captured an ARP packet\n");
    }
    else {
        printf("Captured unsupported packet\n");
        printf("Packet identifier: %x\n", ntohs(ether_hdr->ether_type));
        return;
    }
}   

void handle_ip4(const u_char* packet) {
    struct ip* ip_header;          

    ip_header = (struct ip*)(packet);
    int iplen = IP_HEADER_LEN(ip_header);

    printf("=================IP=================\n");
    if (ip_header->ip_v  == IPVERSION) {
        printf("Ipv4 address got\n");
    }
    else{
        printf("Not ip4\n");
        return;
    }

    //extracting the info
    printf("IP Header Length: %d bytes\n", iplen);
    char* srcip = inet_ntoa(ip_header->ip_src);
    printf("The Source Ip is: %s\n", srcip);
    char* dstip = inet_ntoa(ip_header->ip_dst);
    printf("The Destination Ip is: %s\n", dstip);

    if (ip_header->ip_p == IPPROTO_TCP){
        printf("TCP packet captured\n");
        handle_tcp(packet + iplen);
    }
    else if (ip_header->ip_p == IPPROTO_UDP) {
        printf("UDP packet captured\n");
        handle_udp(packet + iplen);
    }
    else {
        printf("Unsupported protocol\n");
        printf("The protocol identifier is %d\n", ip_header->ip_p);
        return;
    }
}   

void handle_tcp(const u_char* packet) {
    printf("=================TCP=================\n");
    struct tcphdr* tcp_header;  
    tcp_header = (struct tcphdr*)(packet);
    int tcplen = TCP_HEADER_LEN(tcp_header);

    printf("TCP header length: %d bytes\n", tcplen);
    printf("Source port: %d\n", ntohs(tcp_header->source));
    printf("Destination port: %d\n",  ntohs(tcp_header->dest));
}

void handle_udp(const u_char* packet) {
    printf("================UDP================\n");
    struct udphdr* udp_header;
    udp_header = (struct udphdr*)(packet);
    int udplen = UDP_HEADER_LEN;

    printf("UDP header length: %d bytes\n", udplen);
    printf("Source Port: %d\n", ntohs(udp_header->source));
    printf("Destination Port: %d\n", ntohs(udp_header->dest));
}