#ifndef MAIN_H
#define MAIN_H

/*-------------------NEEDED NETWORK AND SIGNAL INCLUDE FILES-------------------------*/
#include <pcap.h>
#include <signal.h>
#include <stdint.h>

/*---------------------GLOBAL VARIABLES-------------------------------------------------*/
extern unsigned long long packet_count;
extern volatile sig_atomic_t stopped;

/*---------------------FUNCTION DECLARATIONS FOR MAIN FILE---------------------------------------*/
void signal_handler(int signum, siginfo_t *info, void *context);
int setup_signal_handler();
void print_capture_stats(time_t *start, time_t *stop);
#endif
