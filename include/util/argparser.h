#ifndef ARGPARSER_H
#define ARGPARSER_H

/*---------------------FLAGS FOR INPUTTED OPTIONS----------------------------------*/
#define ALL_FLAG 	0x0001	  //00000001
#define PROMISC_FLAG 	0x0002    //00000010
#define FILTER_FLAG 	0x0004    //00000100
#define IFACE_FLAG 	0x0008	  //00001000
#define HELP_FLAG 	0x0010	  //00010000
#define INPUT_FLAG 	0x0020	  //00100000
#define OUTPUT_FLAG 	0x0040    //01000000
#define MONITOR_FLAG 	0x0080	  //10000000
#define AUTO_FLAG 	0x0100	 //100000000

/*----------------STRUCT FOR USER INPUT--------------------------------------*/
struct userInput {
    unsigned int flags;
    const char *filter;
    const char *interface;
    const char *output_file;
    const char *input_file;
};

int handle_input(int argc, char **argv, struct userInput *input);
#endif
