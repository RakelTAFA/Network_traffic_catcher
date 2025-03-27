#include "DeviceManager.h"


DeviceManager* DeviceManager::device_manager = nullptr;


DeviceManager::DeviceManager()
{
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &all_devices, error_buffer) == -1)
	{
		printf("Error finding devices : %s\n", error_buffer);
	}
	if (converter == nullptr) converter = new DNSConverter();
}


DeviceManager* DeviceManager::getDeviceManager()
{
	if (device_manager == nullptr)
	{
		device_manager = new DeviceManager();
	}
	return device_manager;
}


pcap_if_t* DeviceManager::getSelectedDevice()
{
	return selected_device;
}


vector<website*> DeviceManager::getWebsites()
{
	return websites;
}


void DeviceManager::printDeviceList()
{
	if (all_devices == nullptr)
	{
		printf("There is no device available !\n");
		return;
	}

	printf("Listing all available devices...\n");

	number_of_devices = 0;
	for (pcap_if_t* devs = all_devices; devs != nullptr; devs = devs->next)
	{
		printf("%u.", ++number_of_devices);
		if (devs->description)
		{
			printf(" %s\n", devs->description);
		}
		else
		{
			printf(" %s (No description available)\n", devs->name);
		}
	}
	printf("\n");
}


unsigned short DeviceManager::getNumberOfDevices()
{
	return number_of_devices;
}


unsigned short DeviceManager::getNumberOfWebsites()
{
	return number_of_websites;
}


void DeviceManager::setSelectedDevice(unsigned short int _selected_number)
{
	pcap_if_t* iterator = all_devices;

	for (unsigned short int i = 0; i < _selected_number - 1; i++)
	{
		if (iterator != nullptr)
			iterator = iterator->next;
	}

	// Isolates selected device from the entire list in order not to access the other devices
	if (iterator != nullptr) selected_device = new pcap_if_t(*(iterator));
	selected_device->next = nullptr;
}


void DeviceManager::printSelectedDevice()
{
	if (selected_device != nullptr) printf("You selected %s\n", selected_device->description);
	else printf("No device selected...\n");
}


void DeviceManager::addWebsite(const char* _website)
{
	if (number_of_websites > MAX_NUMBER_OF_WEBSITES)
	{
		return;
	}

	website* new_website = new website();

	if (!converter->convertDnsNameToIPv4(new_website, _website))
	{
		delete new_website;
		return;
	};

	new_website->name = new char[strlen(_website) + 1];
	strcpy_s((char*)new_website->name, strlen(_website) + 1, _website);

	websites.push_back(new_website);
	
	number_of_websites++;
}


void DeviceManager::deleteAllWebsites()
{
	if (websites.size() < 1) return;

	for (website* it : websites)
	{
		if (it->name != nullptr)
			delete[] it->name;

		for (const char* ip : it->ip_addresses)
		{
			delete[] ip;
		}

		delete it;
	}
}


bool DeviceManager::openCapture()
{
	if ((capture = pcap_open(selected_device->name,
		65536,
		0,
		1000,
		nullptr,
		error_buffer
	)) == nullptr)
	{
		printf("\nUnable to open the adapter. %s is not supported by Npcap\n", selected_device->name);
		return false;
	}

	// If promiscuous mode is supported it will be enabled automatically
	pcap_set_promisc(capture, PCAP_OPENFLAG_PROMISCUOUS);

	return true;
}


bool DeviceManager::defineFilter()
{
	// Port 80 for HTTP, port 443 for HTTPS. We filter websites.
	char packet_filter[] = "dst port 80 or dst port 443";

	struct bpf_program filter_code;
	
	// 255.255.255.0 for class C networks
	u_int netmask = 0xFFFFFF;

	// Must never occur since the filter is not defined by the user.
	// May become useful in a future update.
	if (pcap_compile(capture, &filter_code, packet_filter, 1, netmask) < 0)
	{
		printf("\nUnable to compile the packet filter. Check the syntax.\n");
		return false;
	}

	if (int error = pcap_setfilter(capture, &filter_code) != 0)
	{
		printf("\nError %d occured when setting the filter: %s\n", error, pcap_geterr(capture));
		return false;
	}

	return true;
}


void DeviceManager::startCapture()
{
	if (!openCapture()) return;
	if (!defineFilter()) return;

	struct pcap_pkthdr* header = nullptr;
	const u_char* packet_data = nullptr;
	int result;

	ip_header* ip_h;

	while (result = pcap_next_ex(capture, &header, &packet_data) >= 0)
	{
		if (packet_data == nullptr)
			continue;

		ip_h = (ip_header*)(packet_data + ETHERNET_LENGTH);
		char bytes[IP_MAX_LENGTH];
		snprintf(bytes, IP_MAX_LENGTH, "%d.%d.%d.%d", ip_h->dst_addr.byte1, ip_h->dst_addr.byte2, ip_h->dst_addr.byte3, ip_h->dst_addr.byte4);

		for (website* web_it : websites)
		{
			for (const char* char_it : web_it->ip_addresses)
			{
				// We register the connection only once otherwise the console is flooded
				// This works only if there is one user on the network. It'll be adapted to register connection for each user so that each user is traced
				if (!web_it->connection_registered && (string)bytes == (string)char_it)
				{
					printf("Connection to %s from %s detected (server %s).\n", web_it->name, "DEVICE INFO", bytes);
					web_it->connection_registered = true;
				}
			}
		}
	}

	if (result == -1)
	{
		printf("Error reading the packets: %s\n", pcap_geterr(capture));
	}
}


DeviceManager::~DeviceManager()
{
	if (capture != nullptr) pcap_close(capture);
	if (all_devices != nullptr) pcap_freealldevs(all_devices);
	if (converter != nullptr) delete converter;
	if (selected_device != nullptr) delete selected_device;

	deleteAllWebsites();
}