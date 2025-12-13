#include <stdio.h>
#include "../Includes/c_http.h"
#include "../Includes/output_printer.h"


void handle_http(const u_char* packet, int msg_len) {
    print_protocol_header("HTTP");
    fwrite(packet, 1, msg_len, stdout);
    printf("\n");
}
