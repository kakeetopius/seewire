#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include "../Includes/c_ether.h"
#include "../Includes/main.h"
#include "../Includes/messages.h"

unsigned long long packet_count; /*For packet captured count*/
time_t start, stop;		 /*For capture duration*/

int main(int argc, char **argv) {
    struct userInput input;
    int status;

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

    pcap_t* handle = NULL;
    status = set_up_pcap_handle(&handle, &input);
    if (status != 0) {
	return -1;
    }

    time(&start); //capture start time.
    //start capture.
    status = pcap_loop(handle, -1, callback, NULL);
    if (status == 0) {
	//if reading from file and packets are done.
	print_capture_stats();	
    }
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
    
    print_capture_stats();
    exit(0);
}

void print_capture_stats() {
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

    printf("\n\n*************************************\n");
    printf("Stopped Packet Capture......\n");
    printf("Total Packets Captured: %llu\n", packet_count);
    printf("Total Capturing Time: %.2f seconds\n", capture_time);
    printf("Start Time: %s\n", start_buff);
    printf("Stop Time:  %s\n", stop_buff);

}
/*
 * Function callback is called for every packet sent to the process.
 */
void callback(u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet_data) {
    ++packet_count;

    if (hdr->len < 40) {
	return;
    } else if (hdr->len > 1515) {
	return;
    }

    printf("+*+*+*+*+*+*+*+*+*+*+*+*+*+*+*+*+*+*+*+*+*+*+*+*+*+*+*+*+*+**+*+*+*+*+*\n");
    printf("Captured packet\n");
    printf("Total Packet Length:     %d\n", hdr->len);
    printf("Packet Count:            %llu\n", packet_count);

    handle_ethernet(packet_data, hdr->len);
}

/*
 * Function handle_input is used to parse command line arguments supplied by the user and
 * initialise the command options struct
 */
int handle_input(int argc, char **argv, struct userInput *input) {
    if (!input) {
	printf("Uninitialised user input struct");
	return -1;
    }
    input->flags = 0;
    input->filter = NULL;
    input->interface = NULL;
    input->input_file = NULL;
    input->output_file = NULL;

    if (argc < 2) {
	// if no option is given automatically set the ALL_FLAG.
	input->flags = input->flags | ALL_FLAG;
	return 0;
    }

    int i = 1;
    while (i < argc) {
	if (argv[i][0] == '-') {
	    // if the argument is a flag.

	    if (strcmp("-h", argv[i]) == 0 || strcmp("--help", argv[i]) == 0) {
		input->flags = input->flags | HELP_FLAG;
		printf("%s", BANNER);
		printf("%s\n", HELP_MESSAGE);
		return 0;
	    } else if (strcmp("-a", argv[i]) == 0 || strcmp("--auto", argv[i]) == 0) {
		input->flags = input->flags | AUTO_FLAG;
	    } else if (strcmp("-i", argv[i]) == 0 || strcmp("--iface", argv[i]) == 0) {
		if (argc == i + 1) {
		    // if this is the last argument in argument list.
		    printf("No interface given. Use -h for more information\n");
		    return -1;
		}

		input->flags = input->flags | IFACE_FLAG;
		input->interface = argv[i + 1];

		i = i + 2; // skip checking the next argument.
		continue;
	    } else if (strcmp("-f", argv[i]) == 0 || strcmp("--filter", argv[i]) == 0) {
		if (argc == i + 1) {
		    // if this is the last argument in argument list.
		    printf("No Filter given. Use -h for more information\n");
		    return -1;
		}

		input->filter = argv[i + 1];
		input->flags = input->flags | FILTER_FLAG;

		i = i + 2; // skip checking the next argument.
		continue;
	    } else if (strcmp("-p", argv[i]) == 0 || strcmp("--promisc", argv[i]) == 0) {
		input->flags = input->flags | PROMISC_FLAG;
	    } else if (strcmp("-m", argv[i]) == 0 || strcmp("--monitor", argv[i]) == 0) {
		input->flags = input->flags | MONITOR_FLAG;
	    } else if (strcmp("-o", argv[i]) == 0 || strcmp("--output", argv[i]) == 0) {
		if (argc == i + 1) {
		    // if this is the last argument in argument list.
		    printf("No output file name given. Use -h for more information.\n");
		    return -1;
		}

		input->output_file = argv[i + 1];
		input->flags = input->flags | OUTPUT_FLAG;

		i = i + 2; // skip checking the next argument.
		continue;
	    } else if (strcmp("-in", argv[i]) == 0 || strcmp("--input", argv[i]) == 0) {
		if (argc == i + 1) {
		    // if this is the last argument in argument list.
		    printf("No input file name given. Use -h for more information.\n");
		    return -1;
		}

		input->input_file = argv[i + 1];
		input->flags = input->flags | INPUT_FLAG;

		i = i + 2; // skip checking the next argument.
		continue;
	    } else {
		printf("Unknown option: %s. Use -h for more information.\n", argv[i]);
		return -1;
	    }
	} else {
	    printf("Unknown option: %s. Use -h for more information.\n", argv[i]);
	    return -1;
	}

	i++;
    }

    if (input->flags & IFACE_FLAG && input->flags & AUTO_FLAG) {
	printf("Cannot use both --auto and --iface. Use -h for more information\n");
	return -1;
    }
    if (input->flags & IFACE_FLAG && input->flags & INPUT_FLAG) {
	// if both interface and input file are supplied.
	printf("Cannot use both -i and -in. Use -h for more information\n");
	return -1;
    }
    if (input->flags & PROMISC_FLAG && input->flags & INPUT_FLAG) {
	// if setting promiscuous mode with input file.
	printf("Cannot set promiscuous mode when not using a network interface. Use -h for more information.\n");
	return -1;
    }
    if (!(input->flags & IFACE_FLAG) && !(input->flags & AUTO_FLAG)) {
	//if both the --iface the --auto flag are not given but some other flags have been given set the ALL_FLAG.
	input->flags = input->flags | ALL_FLAG;
    } 
    return 0;
}

/*
 * Function set_up_handle is used to apply settings specified by the user to the pcap handle.
 */
int set_up_pcap_handle(pcap_t **handle, struct userInput *user_input) {
    char errbuff[PCAP_ERRBUF_SIZE];
    int status;

    //initialise the pcap library
    status = pcap_init(0, errbuff);
    if (status != 0) {
	printf("Error: %s\n", errbuff);
	return -1;
    }

    // retrieving all interfaces.
    pcap_if_t *all_devs = NULL;
    status = pcap_findalldevs(&all_devs, errbuff);
    if (status != 0) {
	printf("Error: %s\n", errbuff);
	return -1;
    }
    if (!all_devs) {
	printf("Error: Could not find any network interfaces.\n");
	return 0;
    }

    pcap_if_t *tmp_dev = NULL; //for iterating through the linked list.
    pcap_if_t *iface_to_use = NULL;
    //finding an up and running non-loopback interface to use if the --auto flag is given.
    if (user_input->flags & AUTO_FLAG) {
	for (tmp_dev = all_devs; tmp_dev != NULL; tmp_dev = tmp_dev->next) {
	    if (tmp_dev->flags & PCAP_IF_LOOPBACK)
		continue;
	    if (tmp_dev->flags & PCAP_IF_UP && tmp_dev->flags & PCAP_IF_RUNNING) {
		iface_to_use = tmp_dev;
		break;
	    }
	}
	if (!iface_to_use) {
	    printf("Error: Could not find an interface that is up and running.\n");
	    pcap_freealldevs(all_devs);
	    return -1;
	}
    }
    
    //finding the interface that corresponds to the one supplied by the user if the --iface flag is given.
    if (user_input->flags & IFACE_FLAG) {
	for (tmp_dev = all_devs; tmp_dev != NULL; tmp_dev = tmp_dev->next) {
	    if (strcmp(tmp_dev->name, "any") == 0) {
		//skip the "any" device
		continue;
	    }
	    if (strcmp(tmp_dev->name, user_input->interface) == 0) {
		iface_to_use = tmp_dev;
		break;
	    }
	}
	//if at all an interface that corresponds to the one given via --iface is not found.
	if (!iface_to_use) {
	    printf("Error: Could not find interface: %s\n", user_input->interface);
	    pcap_freealldevs(all_devs);
	    return -1;
	}
    }
    
    //finding the interface "any" if at all  --auto or --iface are not given
    if (user_input->flags & ALL_FLAG) {
	for (tmp_dev = all_devs; tmp_dev != NULL; tmp_dev = tmp_dev->next) {
	    if (strcmp(tmp_dev->name, "any") == 0) {
		iface_to_use = tmp_dev;
		break;
	    }
	}
    }
    //if for some reason iface_to_use is still NULL.
    if (!iface_to_use) {
	pcap_freealldevs(all_devs);
	return -1;
    }

    *handle = pcap_create(iface_to_use->name, errbuff);
    if (!handle) {
	printf("Error: %s\n", errbuff);
	pcap_freealldevs(all_devs);
	return -1;
    }

    //setting the different options on the handle as specified by the user.
    if (user_input->flags & PROMISC_FLAG) {
	status = pcap_set_promisc(*handle, 1);
	if (status != 0) {
	    printf("Error setting promiscous mode\n");
	    pcap_freealldevs(all_devs);
	    return -1;
	}
    }
    if (user_input->flags & MONITOR_FLAG) {
	status = pcap_set_rfmon(*handle, 1);
	if (status != 0) {
	    printf("Error setting monitor mode\n");
	    pcap_freealldevs(all_devs);
	    return -1;
	}
    }
    if (user_input->flags & FILTER_FLAG) {
	//setting immediate mode when a filter is to be applied to prevent buffering of incoming packets 
	//to prevent waiting for a very long time when few packets that match the filter are captured.
	status = pcap_set_immediate_mode(*handle, 1);

	if (status != 0) {
	    printf("Error setting immediate mode\n");
	    pcap_freealldevs(all_devs);
	    return -1;
	}
    }

    //Activating the handle.
    status = pcap_activate(*handle);
    if (status != 0) {
	printf("Error: %s\n", pcap_geterr(*handle));
	pcap_freealldevs(all_devs);
	return -1;
    }

    printf("Capturing packets on interface: %s\n", iface_to_use->name);

    //If a filter is required.
    if (user_input->flags & FILTER_FLAG && user_input->filter != NULL) {
	struct bpf_program bpf;
	status = pcap_compile(*handle, &bpf, user_input->filter, 1, PCAP_NETMASK_UNKNOWN);
	if (status != 0) {
	    printf("Error: %s\n", pcap_geterr(*handle));
	    pcap_freealldevs(all_devs);
	    return -1;
	}
	
	status = pcap_setfilter(*handle, &bpf);
	if (status != 0) {
	    printf("Error: %s\n", pcap_geterr(*handle));
	    pcap_freealldevs(all_devs);
	    return -1;
	}

	printf("Filter set: %s\n", user_input->filter);
	pcap_freecode(&bpf);
    }

    pcap_freealldevs(all_devs);
    return 0;
}

