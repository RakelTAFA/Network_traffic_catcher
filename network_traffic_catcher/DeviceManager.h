#pragma once
#include<pcap.h>
#include "DNSConverter.h"
#include "ip_header.h"

// Singleton, because we need only one reusable instance of DeviceManager
class DeviceManager
{
	private:
		static DeviceManager* device_manager;
		pcap_if_t* all_devices;
		char error_buffer[PCAP_ERRBUF_SIZE] = "";
		unsigned short int number_of_devices = 0;
		pcap_if_t* selected_device = nullptr;
		website* websites = nullptr;
		website* website_iterator = nullptr;
		vector<const char*> ip_list;
		unsigned short number_of_websites = 0;
		pcap_t* capture = nullptr;

		DNSConverter* converter = nullptr;

		DeviceManager();
		bool openCapture();
		bool defineFilter();

	public:
		static DeviceManager* getDeviceManager();
		void printDeviceList();
		unsigned short getNumberOfDevices();
		unsigned short getNumberOfWebsites();
		pcap_if_t* getSelectedDevice();
		website* getWebsites();
		void setSelectedDevice(unsigned short int);
		void printSelectedDevice();
		void addWebsite(const char*);
		void deleteAllWebsites();
		void startCapture();

		DeviceManager(DeviceManager& device_manager_copy) = delete;
		void operator=(const DeviceManager&) = delete;
		~DeviceManager();
};

