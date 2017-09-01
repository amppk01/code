#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include "smpp_param.h"

#define DEST_SUBADDRESS		515

int extract_correlate(PDU* pdu, char *buff);

char *time_stamp()
{
	char *timestamp = (char *)malloc(sizeof(char) * 16);
	time_t ltime;
	ltime=time(NULL);
	struct tm *tm;
	tm=localtime(&ltime);
	sprintf(timestamp,"%04d%02d%02d%02d%02d%02d", tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
	return timestamp;
}

char *randstring(size_t length)
{
	static char charset[] = "0123456789";
	char *randomString = NULL;
	if (length)
	{
		randomString = malloc(length +1);
		if (randomString) {
			int key, n, l = (int) (sizeof(charset) -1);
			for (n = 0;n < length;n++)
			{
				key = rand() % l;
				randomString[n] = charset[key];
			}
			randomString[length] = '\0';
		}
	}
	return randomString;
}