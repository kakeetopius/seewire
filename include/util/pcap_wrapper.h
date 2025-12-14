#ifndef PCAP_W_H
#define PCAP_W_H

#include <pcap.h>
#include "util/argparser.h"

/*------STRUCT FOR CONTEXT PARAMTER OF THE CALLBACK FOR PACKETS CAPTURED.*/
struct callbackCtx {
    int dlType;		      // the datalink type returned by pcap.
    pcap_dumper_t *savefile; // the pcap file to save capture if required.
};

int set_up_pcap_handle(pcap_t **handle, struct userInput *user_input);
void savefile_callback(u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet_data);
int capture_packets(pcap_t **handle, pcap_handler callback, struct callbackCtx *ctx, struct userInput *user_input);
void packet_capture_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

#endif
