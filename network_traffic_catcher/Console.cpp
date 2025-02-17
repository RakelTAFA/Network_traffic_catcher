#include "Console.h"

Console::Console()
{
	device_manager = DeviceManager::getDeviceManager();
}


void Console::openConsole()
{
	printf("Enter one of the following command,\n\n");
	for (map<const char*, const char*>::iterator itr = input_choices.begin(); itr != input_choices.end(); ++itr)
	{
		printf("%s\n", itr->first);
		printf("\t%s\n\n", itr->second);
	}
}


void Console::handleTargetCommand(string _command)
{
	device_manager->deleteAllWebsites();

	// Removes unnecessary whitespaces at the end if needed
	while (_command.back() == ' ')
	{
		_command.pop_back();
	}
	// Adds only one whitespace to avoid out of bands array error
	_command.push_back(' ');

	while (_command.length() > 0)
	{
		string website = _command.substr(0, _command.find(" "));
		device_manager->addWebsite(website.c_str());
		_command.erase(_command.begin(), _command.begin() + website.length() + 1);
	}
}


void Console::handleSelectCommand(string _command)
{
	unsigned short int device_number;
	try {
		device_number = stoi(_command);
		if (device_number > device_manager->getNumberOfDevices() || device_manager == 0)
			throw out_of_range("");
		device_manager->setSelectedDevice(device_number);
		device_manager->printSelectedDevice();
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


void Console::handleUserInput()
{	
	while (true)
	{
		printf("> ");
		getline(cin, user_input);

		// First word in command
		string input_treatment = user_input.substr(0 , user_input.find(" "));

		if (input_treatment == "Exit")
		{
			printf("Closing the program.\n");
			return;
		}
		else if (input_treatment == "Target")
		{
			user_input.erase(user_input.begin(), user_input.begin() + input_treatment.length() + 1);
			handleTargetCommand(user_input);
		}
		else if (input_treatment == "Select")
		{
			user_input.erase(user_input.begin(), user_input.begin() + input_treatment.length() + 1);
			handleSelectCommand(user_input);
		}
		else if(input_treatment == "Launch")
		{
			device_manager->startCapture();
		}
		else {
			printf("Incorrect input, try again.\n");
		}
		printf("\n");
	}

}