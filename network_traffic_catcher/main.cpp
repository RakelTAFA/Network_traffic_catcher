#include<csignal>
#include "Console.h"
#include "ip_header.h"
#include "tcp_header.h"

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

}


void stop_program(int s)
{
	printf("Closing the programm.\n");
	//pcap_breakloop(stop_program, capture); --> TODO: Implémenter structure pour accéder à l'objet capture
	delete DeviceManager::getDeviceManager();
	exit(1);
}