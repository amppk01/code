/*
history
1.1.05052017	[Create] correlate Project Pegazus.
*/
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include "correlate.h"
#include "sflog.h"

/* Return code
    0 = Success
    1 = User default
    2 = Skip message
    3 = Use last session
*/
int extract_correlate (char *ber, int blen, char *corr)
{
	char *start_p, *end_p, *tmp;
	int len;
	tmp ="PIN_BWOID";
	start_p = strstr(ber, tmp);
	if(start_p != NULL)
	{
		start_p += strlen(tmp);
		start_p = strstr(start_p, " ");
		if(start_p != NULL)
		{
			start_p++;
			end_p = strstr(start_p, "\n");
			if(end_p != NULL)
			{
				len = (end_p - start_p);
				if((len) > 0)
				{
					memcpy(corr, start_p, len);
					corr[len] = 0x0;
					return CORR_SUCCESS;
				}
			}
		}
	}
	return CORR_DEFAULT;
}
