/*
history
1.1.21062017	[Create] correlate Project Pegazus 21.06.2017.
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
	char *start_p, *end_p, *tmp, order_no[MAX_CORR], req_user[MAX_CORR];
	int len;
	
	//!-- correlate logic
	order_no[0] = 0x0;
	req_user[0] = 0x0;

	tmp ="ORDER_NO";
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
					memcpy(order_no, start_p, len);
					order_no[len] = 0x0;
				}
			}
		}
	}
	tmp ="REQ_USER";
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
					memcpy(req_user, start_p, len);
					req_user[len] = 0x0;
				}
			}
			else{
				len = strlen(start_p);
				if((len) > 0)
				{
					memcpy(req_user, start_p, len);
					req_user[len] = 0x0;
				}
			}
		}
	}
	if(order_no[0] != 0x0 && req_user[0] != 0x0){
		sprintf(corr, "%s%s", order_no, req_user);
		return CORR_SUCCESS;
	}else{
		return CORR_DEFAULT;
	}
	
}
