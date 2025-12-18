#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "util/messages.h"
#include "util/output_printer.h"

// Function print_banner() prints to stdout the program's banner.
void print_banner() {
    printf(BANNER);
}

// Function print_protocol_header() is called by the packet parsers to print the protocol name to stdout in a
// uniform way.
void print_protocol_header(char *protocol_name) {
    int name_len = strlen(protocol_name);

    char *dash = "-------------------------------------------------------------";
    int len_to_print = 60;
    int dash_num = (len_to_print - 4 - name_len) / 2;
    int odd = 0;
    if (name_len % 2) {
	odd = 1;
    }
    printf("%.*s[ %s ]%.*s\n", dash_num, dash, protocol_name, odd ? dash_num + 1 : dash_num, dash);
}

// Function print_field() is called by protocol parsers to print packet header information in a uniform way.
void print_field(char *name, void *value, enum valueType value_type) {
    if (value_type == STRING)
	printf("%*s%*s%s\n", -20, name, 10, " ", (char *)value);
    else if (value_type == INTEGER)
	printf("%*s%*s%u\n", -20, name, 10, " ", *(unsigned int *)value);
    else if (value_type == UINT_8)
	printf("%*s%*s%u\n", -20, name, 10, " ", *(uint8_t *)value);
}

void print_field2(char* name, void* value, enum valueType value_type) {
    if (value_type == STRING)
	printf("    %*s%*s%s", -15, name, 5, " ", (char *)value);
    else if (value_type == INTEGER)
	printf("    %*s%*s%u", -15, name, 5, " ", *(unsigned int *)value);
    else if (value_type == UINT_8)
	printf("    %*s%*s%u", -15, name, 5, " ", *(uint8_t *)value);
    else if (value_type == UINT_16)
	printf("    %*s%*s%u", -15, name, 5, " ", *(uint16_t *)value);
}
