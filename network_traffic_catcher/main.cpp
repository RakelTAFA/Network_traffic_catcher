#include<csignal>
#include<sstream>
#include "DNSConverter.h"
#include "Console.h"
#include "DeviceManager.h"
#include "ip_header.h"
#include "tcp_header.h"
using namespace std;

void packet_handler(u_char*, const struct pcap_pkthdr*, const u_char*);
void stop_program(int);

int main()
{
	// Handle Control C command differently
	signal(SIGINT, stop_program);

	DeviceManager* deviceManager = DeviceManager::getDeviceManager();
	deviceManager->printDeviceList();

	Console console;
	console.openConsole();
	console.handleUserInput();

	delete DeviceManager::getDeviceManager();

	deviceManager->startCapture();

	return 0;
}


void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	ip_header* ip_h;
	tcp_header* tcp_h;

	// Unused variable
	(VOID)(param);

	// 14 = Ethernet header length, we skip it to access IPv4 header layer
	ip_h = (ip_header*)(pkt_data + 14);

	// version_ip_header_length contains 2 values : version (4 left bits) and ip_header_length (4 right bits)
	// We want to extract the second value, 0xF = 0000 1111. The following line extracts only the last 4 bits we need.
	// We multiply by 4 to acces the end of the IP Header ad the beginning of the TCP Header.
	u_int ip_len = (ip_h->version_ip_header_length & 0xF) * 4;

	tcp_h = (tcp_header*)((u_char*)ip_h + ip_len);

	//struct sockaddr_in sa;
	//char host[NI_MAXHOST] = "";
	//char serv[NI_MAXSERV] = "";

	//sa.sin_family = AF_INET;
	//sa.sin_port = 443;

	//printf("%d.%d.%d.%d\n", ip_h->dst_addr.byte1, ip_h->dst_addr.byte2, ip_h->dst_addr.byte3, ip_h->dst_addr.byte4);

	//ostringstream ip_address_stream;
	//ip_address_stream << (int)ip_h->dst_addr.byte1 << '.' << (int)ip_h->dst_addr.byte2 << '.' << (int)ip_h->dst_addr.byte3 << '.' << (int)ip_h->dst_addr.byte4;
	//
	//// We need to convert a string into a const char* to run the following function
	//string ip_address_raw = ip_address_stream.str();
	//const char* ip_address_string = ip_address_raw.c_str();
	//
	//inet_pton(AF_INET, ip_address_string, &sa.sin_addr);

	//if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, NI_MAXHOST, serv, NI_MAXSERV, NI_NUMERICSERV) == 0)
	//{
	//	printf("Resolved : %s\n", host);
	//}
	//else
	//{
	//	printf("Impossible to resolve DNS Name (ERROR %d).\n", WSAGetLastError());
	//}

	//WSACleanup();
	
	// TEST
	/*char test[NI_MAXHOST];
	inet_ntop(AF_INET, ip_address_string, test, NI_MAXHOST);
	printf("test : %s\n", test);*/

	struct addrinfo* result = NULL;
	struct addrinfo* ptr = NULL;
	struct addrinfo hints;

	LPSOCKADDR sockaddr_ip;

	char ipstringbuffer[46];
	DWORD ipbufferlength = 46;

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	DWORD retval;

	string tcp_port = "" + tcp_h->dst_port;

	retval = getaddrinfo("www.stackoverflow.com" , tcp_port.c_str(), &hints, &result);
	if (retval != 0)
	{
		printf("getaddrinfo failed with error: %d\n", retval);
		return;
	}

	int iRetval, i = 1;
	struct sockaddr_in* sockaddr_ipv4;
	char retour[NI_MAXHOST];
	
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

		printf("getaddrinfo response %d\n", i++);
		printf("\tFlags: 0x%x\n", ptr->ai_flags);
		printf("\tFamily: ");
		switch (ptr->ai_family) {
		case AF_UNSPEC:
			printf("Unspecified\n");
			break;
		case AF_INET:
			printf("AF_INET (IPv4)\n");
			sockaddr_ipv4 = (struct sockaddr_in*)ptr->ai_addr;
			printf("\tIPv4 address %s\n",
				inet_ntop(AF_INET, &sockaddr_ipv4->sin_addr, retour, NI_MAXHOST));
			break;
		}
	}

	freeaddrinfo(result);
}


void stop_program(int s)
{
	printf("Closing the programm.\n");
	//pcap_breakloop(stop_program, capture); --> TODO: Impl�menter structure pour acc�der � l'objet capture
	delete DeviceManager::getDeviceManager();
	exit(1);
}