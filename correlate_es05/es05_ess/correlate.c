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

int extract_correlate(char *ber, int blen, char *corr)
{
    char *start, *end, tag[2048];
    int length;
    
    memset(corr, 0, MAX_CORR);
	if (!ber || !corr) {
		SFLOG_ERROR("Invalis parameter.");
		return -1;
    }

	//!-- correlate logic
	tag[0] = 0x0;

	start = strstr(ber, "<SS7AP");
	if (start != NULL)
	{
		//start += 6;
		end = strstr(start+6, ">");
		if(end != NULL)
		{
			length = (end - start);
			if((length) > 0 && length < MAX_CORR)
			{
				memcpy(tag, start, length);
				tag[length] = 0x0;
				//SFLOG_DEBUG("tag[%s]", tag);

				if(tag != NULL){
					start = strstr(tag, "session=\"");
					if (start != NULL)
					{
						start += 9;
						end = strstr(start, "\"");
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
					}
				}
			}
		}
	}
    return 1;
}
