#ifndef MESSAGES_H
#define MESSAGES_H

#define HELP_MESSAGE  "Usage: seewire [OPTIONS]\n" \
		      "By default if no options are given, seewire captures all packets on all available network interfaces.\n\n"\
		      "Options:\n" \
		      "-h,  --help	         \tShow this help message.\n"\
		      "-a,  --auto		 \tCapture packets on the first non-loopback network interface found that is up and running.\n" \
		      "-f,  --filter FILTER      \tA filter to apply on the packets captured on an interface. If --iface or --auto is not given the filter is applied on all interfaces.\n" \
		      "-i,  --iface INTERFACE    \tA network interface to capture packets from only.\n"\
		      "-p,  --promisc            \tSet promiscous mode on the interface.\n" \
		      "-m,  --monitor            \tSet monitor mode. This is only relevant for some wifi adapters. When used it is best to also supply the interface.\n" \
		      "-o,  --output FILE        \tSave captured packets to a pcap file called FILE.\n" \
		      "-in, --input FILE         \tStream packets from a pcap file FILE instead of a network interface.\n"

#define BANNER		"  _________             __      __.__                \n" \
			" ╱   _____╱ ____   ____╱  ╲    ╱  ╲__│______   ____  \n" \
			" ╲_____  ╲_╱ __ ╲_╱ __ ╲   ╲╱╲╱   ╱  ╲_  __ ╲_╱ __ ╲ \n" \
                        " ╱        ╲  ___╱╲  ___╱╲        ╱│  ││  │ ╲╱╲  ___╱ \n" \
                        "╱_______  ╱╲___  >╲___  >╲__╱╲  ╱ │__││__│    ╲___  >\n" \
                        "        ╲╱     ╲╱     ╲╱      ╲╱                  ╲╱ \n\n"
    
#endif
