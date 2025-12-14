#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "main.h"
#include "net/datalink.h"
#include "util/output_printer.h"
#include "util/pcap_wrapper.h"

int capture_packets(pcap_t **handle, pcap_handler callback, struct callbackCtx *ctx, struct userInput *user_input) {
    int fd = pcap_get_selectable_fd(*handle);
    fd_set fds;
    struct timeval tv;
    int status;
    char errbuff[PCAP_ERRBUF_SIZE];

    // first determine which link layer type.
    int linktype = pcap_datalink(*handle);
    ctx->dlType = linktype;
    if (fd != -1) {
	// if device supports select()
	while (!stopped) {
	    FD_ZERO(&fds);
	    FD_SET(fd, &fds);

	    tv.tv_sec = 0;
	    tv.tv_usec = 100; // 100ms

	    int ret = select(fd + 1, &fds, NULL, NULL, &tv);
	    if (ret < 0) {
		if (errno == EINTR && stopped) {
		    // if signal sent.
		    printf("\nInterrupted by user......\n");
		} else {
		    perror("select");
		    return 1;
		}
	    } else if (ret > 0) {
		// The kernel packet buffer is guaranteed to have packets so pcap_dispatch() will
		// not block waiting for packets.
		// -1 for cnt parameter such that it processes all available packets and return.
		status = pcap_dispatch(*handle, -1, callback, (u_char *)ctx);
		if (status < 0) {
		    // error from pcap.
		    return status;
		}
		if (status == 0 && user_input->flags & INPUT_FLAG) {
		    // EOF reached when reading from a pcap file.
		    return 0;
		}
	    }
	    // else if ret == 0 - timeout occured so loop again.
	}
    } else {
	printf("Does not support select()\n");
	// Device not selectable: fallback to non-blocking + polling
	if (pcap_setnonblock(*handle, 1, errbuff) < 0) {
	    fprintf(stderr, "Error setting non-blocking mode: %s\n", errbuff);
	    return 1;
	}

	while (!stopped) {
	    status = pcap_dispatch(*handle, -1, callback, (u_char *)ctx);
	    if (status < 0) {
		return status;
	    }
	    if (status == 0 && user_input->flags & INPUT_FLAG) {
		// EOF reached.
		return 0;
	    }
	    usleep(1000); // avoid busy loop
	}
    }

    return 0;
}
/*
 * Function callback is called for every packet sent to the process.
 */
void packet_capture_callback(u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet_data) {
    ++packet_count;
    struct callbackCtx *ctx = (struct callbackCtx *)user;

    if (hdr->len < 40) {
	return;
    } else if (hdr->len > 1515) {
	return;
    }

    printf("─────────────────────────────────────────────────────────────────────────\n");
    printf("Captured packet\n");
    print_field("Total Packet Length:", (void *)&hdr->len, INTEGER);
    print_field("Packet Count:", &packet_count, INTEGER);

    handle_datalink(packet_data, ctx->dlType, hdr->len);
}

/*
 * Function savefile_callback is called for every packet sent to the process if dumping to a pcap file is required.
 */
void savefile_callback(u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet_data) {
    ++packet_count;

    struct callbackCtx *ctx = (struct callbackCtx *)user;
    pcap_dump((u_char *)ctx->savefile, hdr, packet_data);
}

int set_up_pcap_handle(pcap_t **handle, struct userInput *user_input) {
    char errbuff[PCAP_ERRBUF_SIZE];
    int status;

    // initialise the pcap library
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
	return -1;
    }

    pcap_if_t *tmp_dev = NULL; // for iterating through the linked list.
    pcap_if_t *iface_to_use = NULL;
    // finding an up and running non-loopback interface to use if the --auto flag is given.
    if (user_input->flags & AUTO_FLAG) {
	for (tmp_dev = all_devs; tmp_dev != NULL; tmp_dev = tmp_dev->next) {
	    if (tmp_dev->flags & PCAP_IF_LOOPBACK)
		continue;
	    if (strcmp(tmp_dev->name, "any") == 0) {
		// skip the "any" device
		continue;
	    }
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

    // finding the interface that corresponds to the one supplied by the user if the --iface flag is given.
    if (user_input->flags & IFACE_FLAG) {
	for (tmp_dev = all_devs; tmp_dev != NULL; tmp_dev = tmp_dev->next) {
	    if (strcmp(tmp_dev->name, "any") == 0) {
		// skip the "any" device
		continue;
	    }
	    if (strcmp(tmp_dev->name, user_input->interface) == 0) {
		iface_to_use = tmp_dev;
		break;
	    }
	}
	// if at all an interface that corresponds to the one given via --iface is not found.
	if (!iface_to_use) {
	    printf("Error: Could not find interface: %s\n", user_input->interface);
	    pcap_freealldevs(all_devs);
	    return -1;
	}
	// checking to see if it is connected.
	if (!(iface_to_use->flags & PCAP_IF_RUNNING)) {
	    printf("Interface %s seems not to be connected to any network\n", iface_to_use->name);
	    pcap_freealldevs(all_devs);
	    return -1;
	}
    }

    // finding the interface "any" if at all  --auto or --iface are not given
    if (user_input->flags & ALL_FLAG) {
	for (tmp_dev = all_devs; tmp_dev != NULL; tmp_dev = tmp_dev->next) {
	    if (strcmp(tmp_dev->name, "any") == 0) {
		iface_to_use = tmp_dev;
		break;
	    }
	}
    }
    // if for some reason iface_to_use is still NULL and we are not using an input pcap file.
    if (!iface_to_use && !(user_input->flags & INPUT_FLAG)) {
	pcap_freealldevs(all_devs);
	return -1;
    }

    if (user_input->flags & INPUT_FLAG) {
	if (!user_input->input_file) {
	    // if input file is null for some reason
	    pcap_freealldevs(all_devs);
	    return -1;
	}
	*handle = pcap_open_offline(user_input->input_file, errbuff);
    } else {
	*handle = pcap_create(iface_to_use->name, errbuff);
    }

    if (!*(handle)) {
	printf("Error: %s\n", errbuff);
	pcap_freealldevs(all_devs);
	return -1;
    }

    // setting the different options on the handle as specified by the user.
    if (!(user_input->flags & INPUT_FLAG)) {
	// if at all we are capturing from an interface set a sufficient snapshot length of 65535.
	status = pcap_set_snaplen(*handle, 65535);
	if (status != 0) {
	    printf("Error setting snaplen\n");
	    pcap_freealldevs(all_devs);
	    return -1;
	}
    }
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
    if (user_input->flags & FILTER_FLAG && !(user_input->flags & INPUT_FLAG)) {
	// setting immediate mode when a filter is to be applied to prevent buffering of incoming packets
	// to prevent waiting for a very long time when few packets that match the filter are captured.
	status = pcap_set_immediate_mode(*handle, 1);

	if (status != 0) {
	    printf("Error setting immediate mode\n");
	    pcap_freealldevs(all_devs);
	    return -1;
	}
    }

    // if we are using offline file no need to activate handle.
    if (user_input->flags & INPUT_FLAG) {
	printf("Using offline file: %s\n", user_input->input_file);
    } else {
	// setting timeout on handle.
	status = pcap_set_timeout(*handle, 100);
	if (status != 0) {
	    printf("Error: %s\n", pcap_geterr(*handle));
	    pcap_freealldevs(all_devs);
	    return -1;
	}
	status = pcap_activate(*handle);
	if (status != 0) {
	    printf("Error: %s\n", pcap_geterr(*handle));
	    pcap_freealldevs(all_devs);
	    return -1;
	}
	printf("Capturing packets on interface: %s\n", iface_to_use->name);
    }

    // If a filter is required.
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
