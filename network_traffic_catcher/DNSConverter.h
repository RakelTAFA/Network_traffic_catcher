#pragma once
#include<iostream>
#include<WS2tcpip.h>
#pragma comment (lib, "Ws2_32.lib")

class DNSConverter
{
	private:
		WSAData socket = { 0 };

	public:
		DNSConverter();

};

