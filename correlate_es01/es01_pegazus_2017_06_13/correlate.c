/*
history
1.1.13062017	[Create] correlate Project Pegazus 13.06.2017.
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
	char *start_p, *end_p, *tmp, bwoid[MAX_CORR], user[MAX_CORR];
	int len;
	
	//!-- correlate logic
	bwoid[0] = 0x0;
	user[0] = 0x0;

	tmp ="BWOID";
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
					memcpy(bwoid, start_p, len);
					bwoid[len] = 0x0;
				}
			}
		}
	}
	tmp ="USER";
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
					memcpy(user, start_p, len);
					user[len] = 0x0;
				}
			}
			else{
				len = strlen(start_p);
				if((len) > 0)
				{
					memcpy(user, start_p, len);
					user[len] = 0x0;
				}
			}
		}
	}
	if(bwoid[0] != 0x0 && user[0] != 0x0){
		sprintf(corr, "%s%s", bwoid, user);
		//SFLOG_DEBUG("Output[%s]", corr);
		return CORR_SUCCESS;
	}else{
		return CORR_DEFAULT;
	}
	
}
