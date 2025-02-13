#pragma once
#include<pcap.h>

class DeviceManager
{
	private:
		static DeviceManager* device_manager;
		pcap_if_t* all_devices;
		char error_buffer[PCAP_ERRBUF_SIZE] = "";
		pcap_if_t* selected_device = nullptr;

		DeviceManager();

	public:
		static DeviceManager* getDeviceManager();
		void printDeviceList();
		pcap_if_t* getSelectedDevice() { return selected_device; };
		void setSelectedDevice(unsigned short int);
		void printSelectedDevice();

		DeviceManager(DeviceManager& device_manager_copy) = delete;
		void operator=(const DeviceManager&) = delete;
		~DeviceManager();
};

