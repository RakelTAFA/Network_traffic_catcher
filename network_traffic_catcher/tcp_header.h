#pragma once
#include<pcap.h>

/*
* u_char = 1 byte = 8 bits
* u_short = 2 bytes = 16 bits
* u_int = u_long = 4 bytes = 32 bits
*/

typedef struct {
	u_short src_port;
	u_short dst_port;
	u_int sequence_number;
	u_int acknowledgment_number;
	u_char data_offset_reserved;
	u_char flags;
	u_short window;
	u_short checksum;
	u_short urgent_pointer;
} tcp_header;