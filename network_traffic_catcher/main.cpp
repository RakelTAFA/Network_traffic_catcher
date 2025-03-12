#include<csignal>
#include "Console.h"
#include "ip_header.h"
#include "tcp_header.h"

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

	return 0;
}


void stop_program(int s)
{
	printf("Closing the programm.\n");
	delete DeviceManager::getDeviceManager();
	exit(1);
}