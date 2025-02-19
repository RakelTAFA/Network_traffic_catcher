#pragma once
#include<iostream>
#include<stdexcept>
#include<map>
#include<string>
#include "DeviceManager.h"
using namespace std;

class Console
{
	private:
		map<const char*, const char*> input_choices = {
			{"Target", "Type all website connections to catch.\n\tExample: Target www.stackoverflow.com www.wikipedia.org"},
			{"Select", "Select the device you want to use.\n\tExample: Select 2"},
			{"Launch", "Launches the live capture"},
			{"Exit", "Exits the program"}
		};
		string user_input = "";
		DeviceManager* device_manager = nullptr;

		void handleTargetCommand(string);
		void handleSelectCommand(string);

	public:
		Console();
		void openConsole();
		void handleUserInput();

		Console(Console&) = delete;
		
};

