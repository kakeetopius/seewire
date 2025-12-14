#ifndef MAIN_H
#define MAIN_H

/*-------------------NEEDED NETWORK AND SIGNAL INCLUDE FILES-------------------------*/
#include <pcap.h>
#include <signal.h>
#include <stdint.h>

/*---------------------FLAGS FOR INPUTTED OPTIONS----------------------------------*/
#define ALL_FLAG 0x01	  // 00000001
#define PROMISC_FLAG 0x02 // 00000010
#define FILTER_FLAG 0x04  // 00000100
#define IFACE_FLAG 0x08	  // 00001000
#define HELP_FLAG 0x10	  // 00010000
#define INPUT_FLAG 0x20	  // 00100000
#define OUTPUT_FLAG 0x40  // 01000000
#define MONITOR_FLAG 0x80 // 10000000
#define AUTO_FLAG 0x100	  // 100000000

/*----------------STRUCT FOR USER INPUT--------------------------------------*/
struct userInput {
    unsigned int flags;
    const char *filter;
    const char *interface;
    const char *output_file;
    const char *input_file;
};

/*------STRUCT FOR CONTEXT PARAMTER OF THE CALLBACK FOR PACKETS CAPTURED.*/
struct callbackCtx {
    int dlType;		      // the datalink type returned by pcap.
    pcap_dumper_t *savefile; // the pcap file to save capture if required.
};

/*---------------------FUNCTION DECLARATIONS FOR MAIN FILE---------------------------------------*/
void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
int set_up_bpf(pcap_t *handle, struct bpf_program *bp_filter, char *filter);
void signal_handler(int signum, siginfo_t *info, void *context);
int setup_signal_handler();
int handle_input(int argc, char **argv, struct userInput *input);
int set_up_pcap_handle(pcap_t **handle, struct userInput *user_input);
void savefile_callback(u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet_data);
void print_capture_stats(time_t *start, time_t *stop);
int capture_packets(pcap_t **handle, pcap_handler callback, struct callbackCtx *ctx, struct userInput *user_input);
int datalink_header_len(int dlt);
#endif
