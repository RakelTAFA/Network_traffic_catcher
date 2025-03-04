#pragma once
#include<vector>
using namespace std;

#define IP_MAX_LENGTH 16
#define MAX_NUMBER_OF_WEBSITES 100

typedef struct website {
	const char* name;
	vector<const char*> ip_addresses;
	struct website* next;
} website;