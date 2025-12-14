#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "main.h"
#include "util/argparser.h"
#include "util/messages.h"
#include "util/pcap_wrapper.h"

unsigned long long packet_count = 0; /*For packet captured count*/
volatile sig_atomic_t stopped = 0;

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

    // if at all saving to a file is required.
    if (input.flags & OUTPUT_FLAG) {
	pcap_dumper_t *savefile = pcap_dump_open(handle, input.output_file);
	if (!savefile) {
	    printf("Error: %s\n", pcap_geterr(handle));
	    pcap_close(handle);
	    return -1;
	}
	printf("Saving to file: %s\n", input.output_file);
	time(&start); // capture start time.

	ctx.savefile = savefile;
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

    print_capture_stats(&start, &stop);
    pcap_close(handle);
    return 0;
}

/*
 * Function setup_signal_handler is used to create a sigaction and initialise it with
 * data that allows handling of the SIGINT interrupt.
 */
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
}

/*
 * Function signal handler is called when the process is sent a SIGINT signal
 * such that it can print a summary of the packet capturing including details
 * about start and stop capture time, The number of packets captured.
 */
void signal_handler(int signum, siginfo_t *info, void *context) {
    if (info->si_signo != SIGINT) {
	return;
    }

    stopped = 1;
}

void print_capture_stats(time_t *start, time_t *stop) {
    //----Buffers for data and time strings
    char start_buff[30] = "\0";
    char stop_buff[30] = "\0";

    //------Getting info data time info as string-------
    strftime(start_buff, 29, "%I:%M:%S %p %d.%b.%y", localtime(start));
    strftime(stop_buff, 29, "%I:%M:%S %p %d.%b.%y", localtime(stop));

    double capture_time = difftime(*stop, *start);

    printf("\n\n*************************************\n");
    printf("Total Packets Captured: %llu\n", packet_count);
    printf("Total Capturing Time: %.2f seconds\n", capture_time);
    printf("Start Time: %s\n", start_buff);
    printf("Stop Time:  %s\n", stop_buff);
}

