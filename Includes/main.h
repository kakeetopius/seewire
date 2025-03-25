#ifndef MAIN_H
#define MAIN_H

/*-------------------NEEDED NETWORK AND SIGNAL INCLUDE FILES-------------------------*/
#include <signal.h>
#include <stdint.h>
#include <pcap.h>

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

#endif
