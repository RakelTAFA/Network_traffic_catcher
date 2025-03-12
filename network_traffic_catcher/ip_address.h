#pragma once
#include<pcap.h>

#define BYTE_LENGTH 3

typedef struct {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
} ip_address;