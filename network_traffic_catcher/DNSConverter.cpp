#include "DNSConverter.h"


DNSConverter::DNSConverter()
{
	if (WSAStartup(MAKEWORD(2, 2), &socket) != 0)
	{
		printf("Socket related to the DNS converting system failed to start: error %d\n", WSAGetLastError());
	}
}