#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "main.h"
#include "util/argparser.h"
#include "util/messages.h"
#include "util/pcap_wrapper.h"

unsigned long long packet_count = 0; // For packets captured count
volatile sig_atomic_t stopped = 0;   // will be set by signal handler to tell the program to stop capture

int main(int argc, char **argv) {
    struct userInput input;
    int status;
    time_t start, stop; /*For capture duration*/

    status = handle_input(argc, argv, &input);
    if (status != 0) {
	return -1;
    }
    if (input.flags & HELP_FLAG) {
	return 0;
    }

    status = setup_signal_handler();
    if (status != 0) {
	return -1;
    }

    pcap_t *handle = NULL;
    status = set_up_pcap_handle(&handle, &input);
    if (status != 0) {
	return -1;
    }
    if (!handle) {
	return -1;
    }

    printf("%s\n", BANNER);

    // will contain useful information for the callback function for packets captured.
    struct callbackCtx ctx;

    // if at all saving captured packets to a pcap file is required.
    if (input.flags & OUTPUT_FLAG) {
	pcap_dumper_t *savefile = pcap_dump_open(handle, input.output_file);
	if (!savefile) {
	    printf("Error: %s\n", pcap_geterr(handle));
	    pcap_close(handle);
	    return -1;
	}
	printf("Saving to file: %s\n", input.output_file);

	ctx.savefile = savefile;
	time(&start); // capture start time.
	status = capture_packets(&handle, savefile_callback, &ctx, &input);
	pcap_dump_close(savefile);
    } else {
	// normal capturing without saving to file.
	time(&start); // capture start time.
	status = capture_packets(&handle, packet_capture_callback, &ctx, &input);
    }

    time(&stop);
    if (status == PCAP_ERROR) {
	printf("Error: %s\n", pcap_geterr(handle));
	pcap_close(handle);
	return -1;
    }

    print_capture_stats(&handle, &start, &stop, input.flags & INPUT_FLAG);
    pcap_close(handle);
    return 0;
}

//Function setup_signal_handler() is used to create a sigaction and initialise it with
//data that allows handling of the SIGINT interrupt.
int setup_signal_handler() {
    struct sigaction new_action;

    memset(&new_action, '\0', sizeof(new_action));
    new_action.sa_sigaction = signal_handler;
    sigemptyset(&new_action.sa_mask);
    new_action.sa_flags = SA_SIGINFO;

    if (sigaction(SIGINT, &new_action, NULL) < 0) {
	perror("SIGACTION");
	return -1;
    } else
	return 0;
    return 0;
}

//Function signal_handler() is called when the process is sent a SIGINT signal
//such that it can set the stopped variable to signal to packet_capture function to stop.
void signal_handler(int signum, siginfo_t *info, void *context) {
    if (info->si_signo != SIGINT) {
	return;
    }

    stopped = 1;
}


