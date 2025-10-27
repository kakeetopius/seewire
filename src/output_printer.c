#include <stdio.h>
#include <string.h>

void print_banner();
void print_intro();
void print_packet_intro();

int main(void) {
    print_banner();
    print_intro();
    print_packet_intro();
    return 0;
}

void print_banner() {
       const char *banner =
    "  _________             __      __.__                \n"
    " ╱   _____╱ ____   ____╱  ╲    ╱  ╲__│______   ____  \n"
    " ╲_____  ╲_╱ __ ╲_╱ __ ╲   ╲╱╲╱   ╱  ╲_  __ ╲_╱ __ ╲ \n"
    " ╱        ╲  ___╱╲  ___╱╲        ╱│  ││  │ ╲╱╲  ___╱ \n"
    "╱_______  ╱╲___  >╲___  >╲__╱╲  ╱ │__││__│    ╲___  >\n"
    "        ╲╱     ╲╱     ╲╱      ╲╱                  ╲╱ \n"; 
    
    printf("%s\n", banner);
}

void print_intro() {
    printf("[+] Capturing on eth0........................\n");
    printf("[+] Filter Applied: None\n\n");
    return;
}

void print_packet_intro() {
    printf("──────────────────────[ Packet #605 ]────────────────────────────\n");
    printf("Timestamp: 2025-10-26 21:18:31.224183\n");
    printf("Length: 98 bytes\n\n");

    printf("[Ethernet]\n");
    printf("%-10s %-20s\n", "  src:", "00:aa:bb:cf:43:3e");
    printf("%-10s %-20s\n", "  dst:", "00:aa:5b:bf:53:34");
    printf("%-10s %-20s\n", " Ether Type:", "IP (0XC0)");

    printf("[IP]\n");
    printf("  src: 192.168.22.100\n");
    printf("  dst: 192.168.22.103\n");
    printf("  Protocol: TCP\n");


    printf("[TCP]\n");
    printf("  src port: 443\n");
    printf("  dst port: 56783\n");
    printf("  flags: SYN, ACK");
}
 
