#pragma once
#include<iostream>
#include<WS2tcpip.h>
#include "website.h"
#pragma comment (lib, "Ws2_32.lib")

class DNSConverter
{
	private:
		WSAData socket = { 0 };

	public:
		DNSConverter();
		bool convertDnsNameToIPv4(website*, const char*);
};

