#pragma once

static unsigned short int number_of_websites = 0;

typedef struct website {
	const char* name;
	struct website* next;
} website;