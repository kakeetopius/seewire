#ifndef TCP_H
#define TCP_H


#include <sys/types.h>
#include <stdint.h>

struct c_tcp_header {
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t doff_resv;
    uint8_t flags_resv;
    uint16_t win_size;
    uint16_t chksum;
    uint16_t urg_ptr;
};


enum tcp_proto {
    HTTP_TCP = 80,
    HTTPS_TCP = 443,
    SSH_TCP = 22,
    SMB_TCP = 445,
};
//The tcp header len inside the doff_resv field (times 4 to get actual no. of  bytes)
#define TCP_HEADER_LEN(i) ((((((i)->doff_resv)) >> 4 & 0x0F) * 4))

/*----------------------------The flag fields--------------------------------*/
#define URG_FLAG(i) (((i)->flags_resv) & 0x20)
#define ACK_FLAG(i) (((i)->flags_resv) & 0x10)
#define RST_FLAG(i) (((i)->flags_resv) & 0x04)
#define PSH_FLAG(i) (((i)->flags_resv) & 0x08)
#define SYN_FLAG(i) (((i)->flags_resv) & 0x02)
#define FIN_FLAG(i) (((i)->flags_resv) & 0x01)


void handle_tcp(const u_char* packet, int msg_len);

#endif
