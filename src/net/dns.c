#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>

#include "net/dns.h"
#include "util/output_printer.h"

// DNS Header (12 bytes)
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-------------------------------+-------------------------------+
// | Transaction ID (16 bits)      | Flags (16 bits)               |
// +-------------------------------+-------------------------------+
// | Questions (16 bits)           | Answer RRs (16 bits)          |
// +-------------------------------+-------------------------------+
// | Authority RRs (16 bits)       | Additional RRs (16 bits)      |
// +-------------------------------+-------------------------------+
// | Queries / Answers / Records (variable)                              |
// +---------------------------------------------------------------+
void handle_dns(const u_char *packet, int msg_len) {
    /*-----------if the payload is less than the size of the header.----------*/
    if (msg_len < 12) {
	return;
    }

    print_protocol_header("DNS");
    /*-----------Dns header-------------------*/
    struct dns_header *dns_hdr = (struct dns_header *)packet;

    /*-------------Converting header to host byte order--------------*/
    uint16_t trans_id = ntohs(dns_hdr->transaction_id);
    uint16_t flags = ntohs(dns_hdr->flags);

    /*--------------Extracting flag fields--------------------------*/
    int qr = (flags >> 15) & 0x01;	   // Extracting the type of message(Query / Response)
    uint8_t opcode = (flags >> 11) & 0x0F; // 4-bit Opcode
    uint8_t aa = (flags >> 10) & 0x01;	   // 1-bit Authoritative Answer
    uint8_t tc = (flags >> 9) & 0x01;	   // 1-bit Truncated
    uint8_t rd = (flags >> 8) & 0x01;	   // 1-bit Recursion Desired
    uint8_t ra = (flags >> 7) & 0x01;	   // 1-bit Recursion Available
    int qdcount = ntohs(dns_hdr->qdcount);
    int ancount = ntohs(dns_hdr->ancount);
    int nscount = ntohs(dns_hdr->nscount);
    int arcount = ntohs(dns_hdr->arcount);

    /*----------------Printing out header info---------------------------*/
    print_field("Transaction ID:", &trans_id, UINT_8);
    print_field("Message Type:", qr == 0 ? "0 Query" : "1 Response", STRING);
    print_field("Opcode", opcode == 0 ? "0 Standard" : "Non Standard", STRING);
    print_field("Authoritative Ans:", &aa, UINT_8);
    print_field("Truncated:", &tc, UINT_8);
    print_field("RA:", ra == 1 ? "1 recursion available" : "0", STRING);
    print_field("RD:", rd == 1 ? "1 recursion desired" : "0", STRING);
    print_field("QDCOUNT:", &qdcount, INTEGER);
    print_field("ANCOUNT:", &ancount, INTEGER);
    print_field("NSCOUNT:", &nscount, INTEGER);
    print_field("ARCOUNT:", &arcount, INTEGER);

    if (qr == 0)
	handle_query(packet + DNS_HDR_LEN, msg_len - DNS_HDR_LEN, dns_hdr);
    else if (qr == 1)
	handle_response(packet + DNS_HDR_LEN, msg_len - DNS_HDR_LEN, dns_hdr);
}

// DNS Question Section (variable length)
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +---------------------------------------------------------------+
// | QNAME (variable, series of labels, each label: length+chars) |
// +---------------------------------------------------------------+
// | QTYPE (16 bits) | QCLASS (16 bits)                             |
// +---------------------------------------------------------------+
void handle_query(const u_char *message, int msg_len, struct dns_header *dns_hdr) {
    print_protocol_header("DNSQR");

    const u_char *message_end = message + msg_len;
    uint16_t qdcount = ntohs(dns_hdr->qdcount);

    const u_char *name_ptr = message;  //to keep track of start of QNAMEs

    for (int i = 0; i < qdcount; i++) {
	printf("****Query %d****\n", i + 1);
	print_field2("Query name:", "", STRING);
	name_ptr = print_name(message, message_end, name_ptr);
	printf("\n");
	message = name_ptr;//move message to the end of the qname
	
	uint16_t qtype = ntohs(*(uint16_t *)message); /*Getting two byte query type*/
	print_field2("Query Type:", get_qtype(qtype), STRING);
	printf("\n");

	message += 2; //move message past the qtype.
	uint16_t qclass = ntohs(*(uint16_t *)message); /*Extracting the  QCLASS*/
	print_field2("Query Class:", get_qclass(qclass), STRING);
	printf("\n");
    }
}

// DNS Answer / Resource Record Section (variable length)
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +---------------------------------------------------------------+
// | NAME (variable, pointer or label sequence)                     |
// +---------------------------------------------------------------+
// | TYPE (16 bits) | CLASS (16 bits)                               |
// +-------------------------------+-------------------------------+
// | TTL (32 bits)                                                 |
// +---------------------------------------------------------------+
// | RDLENGTH (16 bits) | RDATA (variable, RDLENGTH bytes)         |
// +---------------------------------------------------------------+
void handle_response(const u_char *message, int msg_len, struct dns_header *dns_hdr) {
    print_protocol_header("DNSRR");

    uint16_t flags = ntohs(dns_hdr->flags);
    uint8_t rcode = flags & 0x0F; // 4-bit Response Code
    
    print_field2("Response Code:", get_rcode_str(rcode), STRING);
    printf("\n");

    const u_char *message_start = message;
    const u_char *message_end = message + msg_len;

    uint16_t qdcount = ntohs(dns_hdr->qdcount);
    uint16_t ancount = ntohs(dns_hdr->ancount);

    const u_char *name_ptr = message; //to keep track of where the QNAMES are.

    /*printing out queries in response*/
    for (int i = 0; i < qdcount; i++) {
	printf("****Query %d****\n", i + 1);
	print_field2("Query Name:", "", STRING);
	name_ptr = print_name(message_start, message_end, name_ptr);
	printf("\n");

	message = name_ptr;//move message to the end of the qname
	uint16_t qtype = ntohs(*(uint16_t *)message); /*Getting two byte query type*/
	print_field2("Query Type:", get_qtype(qtype), STRING);
	printf("\n");
	message += 2; //move message past the qtype.
	
	uint16_t qclass = ntohs(*(uint16_t *)message); /*Extracting the  QCLASS*/
	print_field2("Query Class:", get_qclass(qclass), STRING);
	printf("\n");
	name_ptr = message + 2;
    }

    if (message > message_end) {
	return;
    }

    for (int i = 0; i < ancount; i++) {
	printf("****Response %d****\n", i + 1);
	print_field2("Response For:", "", STRING);
	name_ptr = print_name(message_start, message_end, name_ptr);
	printf("\n");
	
	message = name_ptr;
	uint16_t type = ntohs(*(uint16_t *)(message));
	uint16_t qclass = ntohs(*(uint16_t *)(message + 2));
	uint32_t ttl = ntohl(*(uint32_t *)(message + 4));
	uint16_t dlen = ntohs(*(uint16_t *)(message + 8));
	const u_char *rdata = (message + 10);

	print_field2("Query Type:", get_qtype(type), STRING);
	printf("\n");
	print_field2("Query Class:", get_qclass(qclass), STRING);
	printf("\n");
	print_field2("TTL:", &ttl, INTEGER);
	printf(" seconds \n");
	print_field2("Data Len:", &dlen, UINT_16);
	printf("\n");
	handle_rdata(rdata, type, dlen, message_start, message_end);

	name_ptr = message + 10 + dlen; // moving the name_ptr to next name
    }
    printf("\n");
}

void handle_rdata(const u_char *data, enum query_types type, int len, const u_char *start, const u_char *end) {
    /*Start is included to help in printing the domain name in cname*/
    if ((data + len) > end) {
	return;
    }

    print_field2("Record:", "", STRING);

    if (type == A) {
	struct in_addr *ipaddr = (struct in_addr *)data;
	char ipaddr_str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, ipaddr, ipaddr_str, INET_ADDRSTRLEN);
	printf("%s", ipaddr_str);
    } else if (type == AAAA) {
	struct in6_addr *ipaddr = (struct in6_addr *)data;
	char ipaddr6_str[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, ipaddr, ipaddr6_str, INET6_ADDRSTRLEN);
	printf("%s", ipaddr6_str);
    } else if (type == CNAME) {
	print_name(start, end, data);
    } else if (type == MX) {
	uint16_t preference = ntohs(*(uint16_t *)(data));
	const u_char *mail = (data + 2); /*Plus two to jump preference*/
	print_name(start, end, mail);
	printf(" (Pref %d)", preference);
    } else if (type == TXT) {
	uint8_t len = *(uint8_t *)(data);
	const u_char *txt = (data + 1);
	printf("%.*s", len, txt);
    } else if (type == NS) {
	print_name(start, end, data);
    }
    printf("\n");
}

const u_char *print_name(const u_char *start, const u_char *end, const u_char *name_ptr) {
    /*Explanation of the paramaters*/
    /*
	start---- The beginning of the dns message(qdata) after the dns header. ie exactly 12 bytes from the beginning of entire dns message
	end------ The end of the entire dns packet to prevent overflow
	name_ptr--A pointer to where the name is suspected to be within the message.
    */
    // Returns the start of the next query or response

    // Example format of an encoded name with no pointers
    // 03 'w' 'w' 'w' 06 'g' 'o' 'o' 'g' 'l' 'e' 03 'c' 'o' 'm' 00

    int word_len = *name_ptr;	  // get the length of the first word.
    u_char *pos_after_ptr = NULL; // will store the position after a pointer.
    int has_pointer = 0;

    // loop until we reach the last null terminator 00
    while (word_len != 0) {
	// follow the pointers until we find an actual word to print.
	while ((*name_ptr & 0xc0) == 0xc0) {
	    has_pointer = 1;
	    // extracting the bottom 6 bits of the upper part of the offset and then pushing them up 8 bits to make room for the lower part
	    // of offset
	    int name_offset = (*name_ptr & 0x3F) << 8;
	    // appending the bottom 8 bits of the offset to the upper one to get complete offset.
	    name_offset = name_offset + name_ptr[1];
	    // subtracting 12 to skip thee general dns header
	    name_offset -= 12;

	    if (!pos_after_ptr) {
		// only update the position after pointer once.
		pos_after_ptr = (u_char *)name_ptr + 2; // add two because the pointer is 2 bytes.
	    }

	    // move the name_pointer to correct offset from the start of the dns response.
	    name_ptr = start + name_offset;
	    // update the length
	    word_len = *name_ptr;
	}

	name_ptr++; // move name pointer to first letter.
	printf("%.*s", word_len, name_ptr);

	name_ptr += word_len; // move name_ptr to next word_len
	word_len = *name_ptr; // extract the new word length.
	if (word_len != 0) {
	    printf(".");
	}
    }

    if (has_pointer) {
	return pos_after_ptr;
    }
    // else return the position after the null terminator
    return ++name_ptr;
}

char *get_qtype(enum query_types type) {
    switch (type) {
    case A:
	return "A";
    case NS:
	return "NS";
    case CNAME:
	return "CNAME";
    case SOA:
	return "S0A";
    case PTR:
	return "PTR";
    case MX:
	return "MX";
    case TXT:
	return "TXT";
    case AAAA:
	return "AAAA";
    case SRV:
	return "SRV";
    case CAA:
	return "CAA";
    case ANY:
	return "ANY";
    case HTTPS_RR:
	return "HTTPS_RR";
    default:
	return "OTHER";
    }
}

char *get_qclass(enum query_class qclass) {
    switch (qclass) {
    case IN:
	return "IN";
    case CS:
	return "CS";
    case CH:
	return "CH";
    case HS:
	return "HS";
    case ANY_CLASS:
	return "ANY";
    default:
	return "OTHER";
    }
}

char *get_rcode_str(int rcode) {
    switch (rcode) {
    case 0:
	return "0 No error";
    case 1:
	return "1 Format Error";
    case 2:
	return "2 Server Error";
    case 3:
	return "3 Non-Existent Domain";
    case 4:
	return "4 Not Implemented";
    case 5:
	return "5 Query Refused";
    default:
	return "Other Code";
    }
}
