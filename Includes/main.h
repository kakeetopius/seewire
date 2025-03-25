#ifndef MAIN_H
#define MAIN_H

/*-------------------NEEDED NETWORK AND SIGNAL INCLUDE FILES-------------------------*/
#include <signal.h>
#include <stdint.h>
#include <pcap.h>

/*--------------------------DNS HEADER 12BYTES------------------------------------*/
struct dns_header {
    uint16_t transaction_id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

/*---------------------FLAGS FOR INPUTTED OPTIONS----------------------------------*/
#define A_FLAG 0x01  //00000001
#define P_FLAG 0x02  //00000010
#define F_FLAG 0x04  //00000100


/*---------------------FUNCTION DECLARATIONS FOR MAIN FILE---------------------------------------*/
void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
int handle_input(int argc, char** argv, char** filter);
pcap_t* set_up_handle(int flags, char* interface);
int set_up_bpf(pcap_t* handle, struct bpf_program* bp_filter, char* filter);
void signal_handler(int signum, siginfo_t* info, void* context);
int setup_signal_handler();


void handle_dns(const u_char* packet, int msg_len);
void print_dns_message(const u_char* packet, int msg_len, int qr);

#endif
