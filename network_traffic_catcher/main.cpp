#include<iostream>
#include<string>
#include<stdexcept>
#include<csignal>
#include "ip_header.h"
#include "tcp_header.h"
using namespace std;


void packet_handler(u_char*, const struct pcap_pkthdr*, const u_char*);
void stop_program(int);


int main()
{
	// Handle Contorl C command differently
	signal(SIGINT, stop_program);

	pcap_if_t* all_devices = NULL;
	char error_buffer[PCAP_ERRBUF_SIZE];
	unsigned short int number_of_devices = 0;

	// Search for all available devices
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &all_devices, error_buffer) == -1)
	{
		printf("Error finding devices : %s\n", error_buffer);
		return -1;
	}
	if (all_devices == NULL) return -1;

	printf("Listing all available devices...\n");

	for (pcap_if_t* devs = all_devices; devs != NULL; devs = devs->next)
	{
		printf("%d.", ++number_of_devices);
        if (devs->description)
        {
            printf(" %s\n", devs->description);
        }
		else
			printf(" %s (No description available)\n", devs->name);
	}

	unsigned short int device_number_selected;
	string device_input_choice;
	
	while (true)
	{
		cout << "\nSelect a device to use for packet capture by its number and press Enter: ";
		cin >> device_input_choice;

		try {
			device_number_selected = stoi(device_input_choice);
			if (device_number_selected > number_of_devices || device_number_selected == 0)
				throw out_of_range("");
			break;
		}
		catch (const invalid_argument& arg)
		{
			cerr << "Invalid argument, waiting for an integer" << endl;
		}
		catch (const out_of_range& arg)
		{
			cerr << "Number out of range, enter another number" << endl;
		}
	}

	pcap_if_t* selected_device = all_devices;
	
	for (int i = 0; i < device_number_selected - 1; i++)
	{
		if (selected_device != NULL)
			selected_device = selected_device->next;
	}

	if (selected_device == NULL)
	{
		printf("Error while selecting device...\n");
		pcap_freealldevs(all_devices);
		return -1;
	}

	printf("\nYou selected %s", selected_device->description);

	pcap_t* capture;
	if ((capture = pcap_open(selected_device->name,
		65536,
		0, // My PC doesn't support promiscuous mode
		1000,
		NULL,
		error_buffer
	)) == NULL)
	{
		printf("\nUnable to open the adapter. %s is not supported by Npcap\n", selected_device->name);
		pcap_freealldevs(all_devices);
		return -1;
	}

	printf("\nListening on %s...\n", selected_device->description);

	// Port 80 for HTTP, port 443 for HTTPS : we filter websites
	char packet_filter[] = "port 80 or port 443";
	struct bpf_program filter_code;
	u_int netmask = 0xFFFFFF; // = 255.255.255.0, for class C networks

	if (pcap_compile(capture, &filter_code, packet_filter, 1, netmask) < 0)
	{
		printf("\nUnable to compile the packet filter. Check the syntax.\n");
		pcap_freealldevs(all_devices);
		return -1;
	}

	if (pcap_setfilter(capture, &filter_code) < 0)
	{
		printf("\nError setting the filter.\n");
		pcap_freealldevs(all_devices);
		return -1;
	}

	pcap_loop(capture, 0, packet_handler, NULL);

	pcap_close(capture);

	pcap_freealldevs(all_devices);
	return 0;
}


void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	struct tm ltime;
	char timestr[16];
	time_t local_tv_sec;

	ip_header* ip_h;
	tcp_header* tcp_h;

	// Unused variable
	(VOID)(param);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	printf("%s,%.6d len:%d\n",
		timestr, header->ts.tv_usec, header->len);

	// 14 = Ethernet header length, we skip it to access IPv4 header layer
	ip_h = (ip_header*)(pkt_data + 14);

	// version_ip_header_length contains 2 values : version (4 left bits) and ip_header_length (4 right bits)
	// We want to extract the second value, 0xF = 0000 1111. The following line extracts only the last 4 bits we need.
	// We multiply by 4 to acces the end of the IP Header ad the beggining of the TCP Header.
	u_int ip_len = (ip_h->version_ip_header_length & 0xF) * 4;

	tcp_h = (tcp_header*)((u_char*)ip_h + ip_len);
	printf("Source port: %d - Destination port: %d\n", tcp_h->src_port, tcp_h->dst_port);
}


void stop_program(int s)
{
	printf("\nSIGNAL : %d\n", s);
	//pcap_breakloop(stop_program, capture); --> TODO: Implémenter structure pour accéder à l'objet capture 
	printf("Closing the programm...\n");
	exit(1);
}