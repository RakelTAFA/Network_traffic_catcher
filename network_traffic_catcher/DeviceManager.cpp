#include "DeviceManager.h"


DeviceManager* DeviceManager::device_manager = nullptr;


DeviceManager::DeviceManager()
{
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &all_devices, error_buffer) == -1)
	{
		printf("Error finding devices : %s\n", error_buffer);
	}
}


DeviceManager* DeviceManager::getDeviceManager()
{
	if (device_manager == nullptr)
	{
		device_manager = new DeviceManager();
	}
	return device_manager;
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
		printf("%d.", ++number_of_devices);
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


unsigned short int DeviceManager::getNumberOfDevices()
{
	return number_of_devices;
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
	if (websites == nullptr)
	{
		websites = new website();
		website_iterator = websites;
	}

	website_iterator->name = new char[strlen(_website) + 1];
	strcpy_s((char*)website_iterator->name, strlen(_website) + 1, _website);

	website_iterator->next = new website();
	website_iterator = website_iterator->next;

	number_of_websites++;
}


void DeviceManager::deleteAllWebsites()
{
	if (websites == nullptr) return;

	website* it = websites;
	website* it_next = it->next;

	// Easiest way of handling deletion
	while (true)
	{
		if (it->name != nullptr)
			delete[] it->name;

		delete it;
		it = it_next;

		if (it == nullptr)
			break;

		it_next = it_next->next;
	}
}


void DeviceManager::startCapture()
{
	//...
	printf("CAPTURE !");
}


DeviceManager::~DeviceManager()
{
	if (all_devices != nullptr) pcap_freealldevs(all_devices);
	if (selected_device != nullptr) delete selected_device;
	deleteAllWebsites();
}