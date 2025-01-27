#include<iostream>
#include<pcap.h>
#include<string>
#include<stdexcept>
using namespace std;


int main()
{
	pcap_if_t* all_devices = NULL;
	char error_buffer[PCAP_ERRBUF_SIZE];
	unsigned short int number_of_devices = 0;

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &all_devices, error_buffer) == -1)
	{
		printf("Error finding devices : %s", error_buffer);
		exit(1);
	}
	if (all_devices == NULL) exit(1);

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
		printf("Error while selecting device...");
		exit(1);
	}

	printf("\nYou selected %s", selected_device->description);

    pcap_open_live(selected_device->name, 4096, 0, 100, error_buffer);

	pcap_freealldevs(all_devices);
	return 0;
}

