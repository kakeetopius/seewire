#ifndef HTTP_H
#define HTTP_H

#include <sys/types.h>

void handle_http(const u_char* packet, int msg_len);

#endif
