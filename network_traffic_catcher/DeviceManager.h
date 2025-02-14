#pragma once
#include<pcap.h>

// Singleton, because we need only one reusable instance of DeviceManager
class DeviceManager
{
	private:
		static DeviceManager* device_manager;
		pcap_if_t* all_devices;
		char error_buffer[PCAP_ERRBUF_SIZE] = "";
		unsigned short int number_of_devices = 0;
		pcap_if_t* selected_device = nullptr;

		DeviceManager();

	public:
		static DeviceManager* getDeviceManager();
		void printDeviceList();
		unsigned short int getNumberOfDevices();
		pcap_if_t* getSelectedDevice() { return selected_device; }
		void setSelectedDevice(unsigned short int);
		void printSelectedDevice();
		void startCapture();

		DeviceManager(DeviceManager& device_manager_copy) = delete;
		void operator=(const DeviceManager&) = delete;
		~DeviceManager();
};

