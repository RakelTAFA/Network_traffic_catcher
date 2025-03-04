#pragma once
#include<vector>
using namespace std;

#define IP_MAX_LENGTH 16

static unsigned short int number_of_websites = 0;

typedef struct website {
	const char* name;
	vector<const char*> ip_addresses;
	struct website* next;
} website;