# Things to implement and improve in due course.
1.  Output of Packet Headers
    - Improve the way packet headers are printed.
    - Add an option to print detailed or print concise.
    - Add an option to save packet headers to a file for later viewing.
2. Support for pcap files.
    - Put an option to accept a pcap file and view it using the program.
    - Put an option to save the raw pcap to a file.
3. Parameters and Flags.
    - Improve on the parsing of input paramaters and flags for better scalability
4. Makefile
    - Change makefile to build binary to the new name.
    - Change the target for compiling the c binaries to use pattern matching.
5. DNS module.
    - Change the function that handles priting of dns domain names to be more understable and prevent recursion.
6. HTTP module.
    - Change the handling of http data. Try to read headers and extract fields.
    - Try to implement a way to display http data that is split into multiple packets as a single entity.
7. Support For other Protocols.
    - WLAN 802.11 frames
    - ICMPv4 and ICMPv6
    - SMTP
    - IPv6

