#ifndef MAIN_H
#define MAIN_H
#include <pcap.h>

/*--------------------MACROS FOR HEADER LENGTHS-----------------------------------*/
#define ETHER_HEADER_LEN (sizeof(struct ether_header))
#define IP_HEADER_LEN(i) ((i)->ip_hl * 4)
#define TCP_HEADER_LEN(i) ((i)->doff * 4)
#define UDP_HEADER_LEN (sizeof(struct udphdr)) 

/*---------------------FLAGS FOR INPUTTED OPTIONS----------------------------------*/
#define A_FLAG 0x01
#define P_FLAG 0x02
#define F_FLAG 0x04


/*---------------------FUNCTION DECLARATIONS FOR MAIN FUNCTION---------------------------------------*/
void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
void handle_ethernet(const u_char* packet);
void handle_ip4(const u_char* packet);
void handle_tcp(const u_char* packet);
void handle_udp(const u_char* packet);
int handle_input(int argc, char** argv, char** filter);
pcap_t* set_up_handle(int flags, char* interface);
int set_up_bpf(pcap_t* handle, struct bpf_program* bp_filter, char* filter);

#endif
