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
	if (selected_device != nullptr) printf("\nYou selected %s", selected_device->description);
	else printf("No device selected...");
}


void DeviceManager::startCapture()
{
	//...
}


DeviceManager::~DeviceManager()
{
	if (all_devices != nullptr) pcap_freealldevs(all_devices);
	if (selected_device != nullptr) delete selected_device;

	if (device_manager != nullptr) delete device_manager;
}