#include <stdio.h>
#include <string.h>

#include "util/argparser.h"
#include "util/messages.h"

int validate_flags(struct userInput *input);

 //Function handle_input() is used to parse command line arguments supplied to the program and
 //initialise the userInput struct for later use.
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

    return validate_flags(input);
}

//Function validate_flags() checks the flags supplied by the user already put into a userInput struct to determine if the combination
//of flags given is valid or not.
int validate_flags(struct userInput *input) {
    // Validating flags.
    int using_iface = 0;
    if (input->flags & IFACE_FLAG || input->flags & AUTO_FLAG) {
	using_iface = 1;
    }
    if (input->flags & IFACE_FLAG && input->flags & AUTO_FLAG) {
	printf("Cannot use both --auto and --iface. Use -h for more information\n");
	return -1;
    }
    if (using_iface && input->flags & INPUT_FLAG) {
	// if both interface and input file are supplied.
	printf("Cannot use -in when using an interface also. Use -h for more information\n");
	return -1;
    }
    if (input->flags & PROMISC_FLAG && input->flags & INPUT_FLAG) {
	// if setting promiscuous mode with input file.
	printf("Cannot set promiscuous mode when not using a network interface. Use -h for more information.\n");
	return -1;
    }
    if (input->flags & MONITOR_FLAG && input->flags & INPUT_FLAG) {
	// if setting promiscuous mode with input file.
	printf("Cannot set monitor mode when not using a network interface. Use -h for more information.\n");
	return -1;
    }
    if (!(input->flags & IFACE_FLAG) && !(input->flags & AUTO_FLAG) && !(input->flags & INPUT_FLAG)) {
	// if both the --iface the --auto flag are not given and we are not using pcap file but some other flags have been given set the ALL_FLAG.
	input->flags = input->flags | ALL_FLAG;
    }
    return 0;
}
