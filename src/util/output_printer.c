#include <stdio.h>
#include <string.h>

#include "util/messages.h"
#include "util/output_printer.h"

void print_banner() {
    printf(BANNER);
}

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

void print_field(char *name, void *value, enum valueType value_type) {
    if (value_type == STRING)
	printf("%*s%*s%s\n", -20, name, 10, " ", (char *)value);
    else if (value_type == INTEGER)
	printf("%*s%*s%u\n", -20, name, 10, " ", *(unsigned int *)value);
}
