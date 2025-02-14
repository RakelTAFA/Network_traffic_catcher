#include "Console.h"

Console::Console()
{
	device_manager = DeviceManager::getDeviceManager();
}


void Console::openConsole()
{
	for (map<const char*, const char*>::iterator itr = input_choices.begin(); itr != input_choices.end(); ++itr)
	{
		printf("%s\n", itr->first);
		printf("\t%s\n\n", itr->second);
	}
}


void Console::handleTargetCommand(string _command)
{
	// TODO
}


void Console::handleSelectCommand(string _command)
{
	// TODO
}


void Console::handleUserInput()
{	
	while (true)
	{
		printf("> ");
		cin >> user_input;
		printf("\n");

		// First word in command
		string input_treatment = user_input.substr(0 , user_input.find(" "));

		// Erase key word from command
		user_input.erase(user_input.begin(), user_input.begin() + input_treatment.length());

		if (input_treatment.compare("Exit"))
		{
			printf("Closing the program.\n");
			return;
		}
		else if (input_treatment == "Target")
		{
			handleTargetCommand(user_input);
		}
		else if (input_treatment == "Select")
		{
			handleSelectCommand(user_input);
		}
		else if(input_treatment == "Launch")
		{
			device_manager->startCapture();
		}
		else {
			printf("Incorrect input, try again.\n");
		}
	}
}