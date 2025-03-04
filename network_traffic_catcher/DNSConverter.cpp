#include "DNSConverter.h"


DNSConverter::DNSConverter()
{
	if (WSAStartup(MAKEWORD(2, 2), &socket) != 0)
	{
		printf("Socket related to the DNS converting system failed to start: error %d\n", WSAGetLastError());
	}
}


bool DNSConverter::convertDnsNameToIPv4(website* _website, const char* _website_name)
{
	char* ip;

	struct addrinfo* result = nullptr;
	struct addrinfo hints;

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	if (DWORD result_value = getaddrinfo(_website_name, "https", &hints, &result) != 0)
	{
		printf("Unable to get address informations on %s: the DNS may not exist...\n", _website_name);
		return false;
	}
	printf("Adding %s:\n", _website_name);

	struct sockaddr_in* sockaddr_ipv4;
	char inet_string_info[NI_MAXHOST];

	for (struct addrinfo* ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
		switch (ptr->ai_family) {
			case AF_UNSPEC:
				printf("Unspecified\n");
				break;

			case AF_INET:
				sockaddr_ipv4 = (struct sockaddr_in*)ptr->ai_addr;
				ip = new char[IP_MAX_LENGTH];
				const char* temp = (char*)inet_ntop(AF_INET, &sockaddr_ipv4->sin_addr, inet_string_info, NI_MAXHOST);
				strcpy_s(ip, strlen(temp) + 1, temp);
				_website->ip_addresses.push_back(ip);
				printf("--> %s\n", ip);
				break;
		}
	}

	freeaddrinfo(result);
	return true;
}