#ifndef MAIN_H
#define MAIN_H

/*-------------------NEEDED NETWORK AND SIGNAL INCLUDE FILES-------------------------*/
#include <signal.h>
#include <stdint.h>
#include <pcap.h>

/*---------------------FLAGS FOR INPUTTED OPTIONS----------------------------------*/
#define ALL_FLAG 0x01         //00000001
#define PROMISC_FLAG 0x02    //00000010
#define FILTER_FLAG 0x04     //00000100
#define IFACE_FLAG 0x08      //00001000
#define HELP_FLAG  0x10     //00010000
#define INPUT_FLAG 0x20     //00100000
#define OUTPUT_FLAG 0x40    //01000000
#define MONITOR_FLAG 0x80   //10000000
#define AUTO_FLAG 0x100	   //100000000

/*----------------STRUCT FOR USER INPUT--------------------------------------*/
struct userInput {
    unsigned int flags;
    const char* filter;
    const char* interface;
    const char* output_file;
    const char* input_file;
};

/*---------------------FUNCTION DECLARATIONS FOR MAIN FILE---------------------------------------*/
void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
int set_up_bpf(pcap_t* handle, struct bpf_program* bp_filter, char* filter);
void signal_handler(int signum, siginfo_t* info, void* context);
int setup_signal_handler();
int handle_input(int argc, char **argv, struct userInput* input);
int set_up_pcap_handle(pcap_t **handle, struct userInput *user_input);
void print_capture_stats();
#endif
