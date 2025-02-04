#pragma once
#include "ip_address.h"

typedef struct {
	u_char version_ip_header_length;
	u_char type_of_service;
	u_short total_length;
	u_short identification;
	u_short flags_fragment_offset;
	u_char ttl;
	u_char protocol;
	u_short checksum;
	ip_address src_addr;
	ip_address dst_addr;
	u_int option_padding;
} ip_header;