#include <stdio.h>
#include "../Includes/c_http.h"


void handle_http(const u_char* packet, int msg_len) {

    printf("|*-----------------------HTTP----------------------*|\n");
    printf("%*s", msg_len, packet);
    printf("\n");
}
