#include<iostream>
#include<pcap.h>
#include<string>
#include<stdexcept>
using namespace std;


void packet_handler(u_char*, const struct pcap_pkthdr*, const u_char*);


int main()
{
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

	(VOID)(param);
	(CHAR)(pkt_data);

	cout << &pkt_data << endl;

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	printf("%s,%.6d len:%d\n",
		timestr, header->ts.tv_usec, header->len);
}