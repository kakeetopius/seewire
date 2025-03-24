#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

#include "../Includes/main.h"

int status; /*For error checking*/
char errbuff[PCAP_ERRBUF_SIZE]; /*For error message*/
unsigned long long packet_count; /*For packet captured count*/
time_t start, stop; /*For capture duration*/

int main(int argc, char** argv) {

    char* filter = (char*)malloc(50 * sizeof(char)); /*For the filter entered.*/

    if (!filter) {
        printf("Malloc Error\n");
        return -1;
    }

    int flags = handle_input(argc, argv, &filter);
    if (flags == -1) {
        exit(-1);
    }
    else if (!(flags & F_FLAG)) {
        free(filter);
    }

    pcap_t* handle = set_up_handle(flags, argv[1]); //argv[1] is the interface to set up the handle
    if (handle == NULL) {
        exit(-1);
    }

    struct bpf_program bp_filter;
    //setting filter
    if (flags & F_FLAG) {
        if(set_up_bpf(handle, &bp_filter, filter) == -1){
            free(filter);
            exit(-1);
        }
        free(filter);
    }

    setup_signal_handler();

    //capture packets in an infinite loop.
    time(&start); // starting time
    pcap_loop(handle, -1, callback, NULL);
    pcap_freecode(&bp_filter);
    pcap_close(handle);
    return 0;
}

int setup_signal_handler() {
    struct sigaction new_action;
    
    /*Setting up new signal action*/
    memset(&new_action, '\0', sizeof(new_action));
    new_action.sa_sigaction = signal_handler;
    sigemptyset(&new_action.sa_mask);
    new_action.sa_flags = SA_SIGINFO;

    if(sigaction(SIGINT, &new_action, NULL) < 0) {
        perror("SIGACTION");
        return -1;
    }
    else 
        return 0;
}

void signal_handler(int signum, siginfo_t* info, void* context) {
    if(info->si_signo != SIGINT) {
       return;
    }

    //---Stopping time----
    time(&stop);

    //----Buffers for data and time strings
    char start_buff[30] = "\0";
    char stop_buff[30] = "\0";
  
    //------Getting info data time info as string-------
    strftime(start_buff, 29, "%I:%M:%S %p %d.%b.%y", localtime(&start));
    strftime(stop_buff, 29, "%I:%M:%S %p %d.%b.%y", localtime(&stop));

    //-------Difference between start and stop-------
    double capture_time = difftime(stop, start);

    printf("*************************************\n");
    printf("Stopping Packet Capture......\n");
    printf("Total Packets Captured: %llu\n", packet_count);
    printf("Total Capturing Time: %.2f seconds\n", capture_time);
    printf("Start Time: %s\n", start_buff);
    printf("Stop Time:  %s\n", stop_buff);
    exit(0);
}

void callback(u_char *user, const struct pcap_pkthdr* hdr, const u_char *packet_data) {
    ++packet_count;
    printf("--------------------------------------------------------------------------------------------------\n");
    printf("Captured packet\nTotal Packet Length: %d\n", hdr->len);
    printf("Packet Count: %llu\n", packet_count);

    handle_ethernet(packet_data);
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

int handle_input(int argc, char** argv, char** filter) {
    char* error_message = "Usage: ./capture <interface> -a to capture all packets.\nUsage: ./capture <interface> -f <filter> to filter the packets\nUse flag -p to set promiscous mode\n";

    int flags = 0;

    if (argc < 3) {
        printf("%s", error_message);
        return -1;
    }

    //===========================handling inputed filters=================================
    char flag;                // for flag arguments
    int f_pos;               // for position of the -f
    int num_args = 2;       //total arguments without filter words; 2 for the program name and the interface.

    //---Checking for flags---
    for (int i = 2; i < argc; i++) {
        if (*(argv[i]) == '-') {
            if(strlen(argv[i]) != 2) {
                printf("Unknown Option: %s\n", argv[i]);
                return -1;
            }
            flag = *(argv[i] + 1);
            switch(flag) {
                case 'p':
                    flags = flags | P_FLAG;
                    num_args++;
                    break;
                case 'a':
                    flags = flags | A_FLAG;
                    num_args++;
                    break;
                case 'f':
                    flags = flags | F_FLAG;
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
    if ((flags & F_FLAG) && (flags & A_FLAG)) {
        printf("Cannot set both -a and -f\n");
        printf("%s\n", error_message);
        return -1;
    }
    else if (flags & A_FLAG) {
        printf("Option: Capture all packets\n");
    }
    else if (flags & F_FLAG) {
        int num_filter_words = argc - num_args;     //minus the rest of arguments

        if (num_filter_words == 0) {
            printf("No filters entered\n");
            printf("%s", error_message);
            return -1;
        }   
       
        int filter_length = 0;
        //----Determing the length of the filter entered.-------
        //----i for checking argv; j for controlling the loop.----
        for (int i = f_pos + 1, j = 0; j < num_filter_words; i++,j++) {
           filter_length = filter_length + strlen(argv[i]) + 1;   // plus one of space between and null terminator for last
        }   
        if (filter_length > 50) {
            printf("Filter too long\n");
            return -1;
        }
        
        //------Appending the filter to the filter buffer with space between arguments
        for (int i = f_pos + 1, j = 0; j < num_filter_words; i++,j++) {
            strcat(*filter, argv[i]);
            strcat(*filter, " ");
        }
        
        printf("Filter entered is: %s\n", *filter);
    }
    else {
        printf("%s", error_message);
        return -1;
    }
    return flags;
}

pcap_t* set_up_handle(int flags, char* interface) {
    status = pcap_init(0, errbuff);
    pcap_t* handle = NULL;
    if (status != 0) {
        printf("Error: %s\n", pcap_strerror(status));
        return NULL;
    }

    handle = pcap_create(interface, errbuff);
    if (handle == NULL) {
        pcap_perror(handle, "Error ");
        return NULL;
    }

    //setting length
    pcap_set_snaplen(handle, 65535);
    
    //setting promiscous mode.
    if (flags & P_FLAG) {
        status = pcap_set_promisc(handle, 1);
        if (status != 0) {
            pcap_perror(handle, "Error set promiscous mode ");
        }
    }
    
    status = pcap_activate(handle);
    if (status != 0) {
        pcap_perror(handle, "Error Activating ");
        return NULL;
    }

    //setting direction
    status = pcap_setdirection(handle, PCAP_D_INOUT);
    if (status != 0) {
        pcap_perror(handle, "Error Setting Direction ");
        return NULL;
    }

    return handle;
}

int set_up_bpf(pcap_t* handle, struct bpf_program* bp_filter, char* filter) {
    status = pcap_compile(handle, bp_filter, filter, 1, PCAP_NETMASK_UNKNOWN);  
    if (status != 0) {
        pcap_perror(handle, "Error BPF ");
        return -1;
    }

    status = pcap_setfilter(handle, bp_filter);

    if (status != 0) {
        pcap_perror(handle, "Error Activating filter \n");
        return -1;
    }

    printf("Filtering packets.....\n");
    return 0;
}