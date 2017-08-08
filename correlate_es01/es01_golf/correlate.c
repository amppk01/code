#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include "correlate.h"
//#include "sflog.h"

/* Return code
    0 = Success
    1 = User default
    2 = Skip message
    3 = Use last session
*/
int extract_correlate (char *ber, int blen, char *corr)
{
	//SFLOG_DEBUG("extract_correlate");
	char *bdata, *start_p, *end_p;
	char bflag = 0;
	int len;
	bdata = (char *) malloc ((blen+1)*sizeof(char));
	if (bdata!=NULL)
	{
		bflag = 1;
		memset(bdata, 0, (blen+1)*sizeof(char));
		memcpy(bdata, ber, blen);
		if (strlen(bdata)<blen) if (bdata[strlen(bdata)]==0) bdata[strlen(bdata)] = 0x20;
		if (strlen(bdata)<blen) if (bdata[strlen(bdata)]==0) bdata[strlen(bdata)] = 0x20;
	}
	else
	{
		bflag = 0;
		bdata = ber;
	}
	memset(corr, 0, MAX_CORR);
	//!-- correlate logic

	start_p = strstr(bdata, "test_es01|");
	if(start_p != NULL)
	{
		start_p+=10;
		end_p = strstr(start_p, "|");
		if(end_p != NULL)
		{
			len = (end_p - start_p);
			if((len) > 0)
			{
				memcpy(corr, start_p, len);
				corr[len] = 0x0;
				//SFLOG_DEBUG("Output[%s]", corr);
			}
		}
	}
	if (bflag==1) free(bdata);
	while ((corr[strlen(corr)-1]==10)||(corr[strlen(corr)-1]==13)) corr[strlen(corr)-1] = '\0';
        return CORR_DEFAULT;
}
