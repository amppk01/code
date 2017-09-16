/*
history
1.1.12092017	[Create] correlate Project ESS.
*/
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "correlate.h"
#include "sflog.h"

#define	CORR_KEY		"SMID="

int extract_correlate(char *ber, int blen, char *corr)
{
    char *start, *end;
    int length;
    
    memset(corr, 0, MAX_CORR);
	if (!ber || !corr) {
		SFLOG_ERROR("Invalid parameter.");
		return -1;
    }

	//!-- correlate logic
	if(strstr(ber, "POST") != NULL)
	{
		start = strstr(ber, CORR_KEY);
		if (start != NULL)
		{
			start += strlen(CORR_KEY);
			end = strstr(start, "&");
			if(end != NULL)
			{
				length = (end - start);
				if((length) > 0 && length < MAX_CORR)
				{
					memcpy(corr, start, length);
					corr[length] = 0x0;
					SFLOG_DEBUG("Correlation [%d][%s]", length, corr);
					return 0;
				}
			}
			else
			{
				end = strstr(start, "\r\n");
				if(end != NULL){
					length = (end - start);
					if(length > 0 && length < MAX_CORR)
					{
						memcpy(corr, start, length);
						corr[length] = 0x0;
						SFLOG_DEBUG("Correlation [%d][%s]", length, corr);
						return 0;
					}
				}
				else{
					length = strlen(start);
					if(length > 0 && length < MAX_CORR)
					{
						memcpy(corr, start, length);
						corr[length] = 0x0;
						SFLOG_DEBUG("Correlation [%d][%s]", length, corr);
						return 0;
					}
				}
			}
		}
	}
    return 1;
}
