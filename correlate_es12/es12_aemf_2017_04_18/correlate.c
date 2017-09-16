/*
history
1.1.18042017	[Create] correlate Project AEMF
*/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "correlate.h"
#include "sflog.h"

int extract_correlate (char *ber, int blen, unsigned int flagment, char *filename, char *corr, int max_buffer)
{
    char *bdata, *start_p, *end_p, *tmp, appName[MAX_CORR], armedEvent[MAX_CORR], armedSubEvent[MAX_CORR], msisdn[MAX_CORR];
    char bflag = 0;
	int len;
    bdata = (char *) malloc ((blen+1)*sizeof(char));
    if (bdata!=NULL) {
        bflag = 1;
        memset(bdata, 0, (blen+1)*sizeof(char));
        memcpy(bdata, ber, blen);
        if (strlen(bdata)<blen) if (bdata[strlen(bdata)]==0) bdata[strlen(bdata)] = 0x20;
        if (strlen(bdata)<blen) if (bdata[strlen(bdata)]==0) bdata[strlen(bdata)] = 0x20;
    } else {
        bflag = 0;
        bdata = ber;
    }
    memset(corr, 0, max_buffer);
    //!-- get correlation logic
	appName[0] = 0x0;
	armedEvent[0] = 0x0;
	armedSubEvent[0] = 0x0;
	msisdn[0] = 0x0;
	
    start_p = bdata;
    if(start_p != NULL)
	{
		if(strstr(start_p, "msisdn") != NULL){
			tmp = "\"msisdn\"";
			start_p = strstr(bdata, tmp);
			if(start_p != NULL)
			{
				start_p += strlen(tmp);
				start_p = strstr(start_p, ":\"");
				if(start_p != NULL)
				{
					start_p += 2;
					end_p = strstr(start_p, "\"");
					if(end_p != NULL)
					{
						len = (end_p - start_p);
						if((len) > 0)
						{
							strncpy(msisdn, start_p, len);
							msisdn[len] = 0x0;
						}
					}
				}
			}
		}
		
		tmp = "\"appName\"";
		start_p = strstr(bdata, tmp);
		if(start_p != NULL)
		{
			start_p += strlen(tmp);
			start_p = strstr(start_p, ":\"");
			if(start_p != NULL)
			{
				start_p += 2;
				end_p = strstr(start_p, "\"");
				if(end_p != NULL)
				{
					len = (end_p - start_p);
					if((len) > 0)
					{
						strncpy(appName, start_p, len);
						appName[len] = 0x0;
					}
				}
			}
		}
		
		tmp = "\"armedEvent\"";
		start_p = strstr(bdata, tmp);
		if(start_p != NULL)
		{
			start_p += strlen(tmp);
			start_p = strstr(start_p, ":\"");
			if(start_p != NULL)
			{
				start_p += 2;
				end_p = strstr(start_p, "\"");
				if(end_p != NULL)
				{
					len = (end_p - start_p);
					if((len) > 0)
					{
						strncpy(armedEvent, start_p, len);
						armedEvent[len] = 0x0;
					}
				}
			}
		}
		
		tmp = "\"armedSubEvent\"";
		start_p = strstr(bdata, tmp);
		if(start_p != NULL)
		{
			start_p += strlen(tmp);
			start_p = strstr(start_p, ":\"");
			if(start_p != NULL)
			{
				start_p += 2;
				end_p = strstr(start_p, "\"");
				if(end_p != NULL)
				{
					len = (end_p - start_p);
					if((len) > 0)
					{
						strncpy(armedSubEvent, start_p, len);
						armedSubEvent[len] = 0x0;
					}
				}
			}
		}
	}
	
	if(msisdn[0] == 0x0)
	{
		if(appName[0] != 0x0 && armedEvent[0] != 0x0 && armedSubEvent[0] != 0x0 )
		{
			sprintf(corr, "%s:%s:%s", appName, armedEvent, armedSubEvent);
			SFLOG_DEBUG("Output[%s]", corr);
		}
		else if(appName[0] != 0x0 && armedEvent[0] != 0x0 && armedSubEvent[0] == 0x0 )
		{
			sprintf(corr, "%s:%s:00", appName, armedEvent);
			SFLOG_DEBUG("Output[%s]", corr);
		}
		else{
			strcpy(corr,randstring(10));
			SFLOG_DEBUG("Output[%s]", corr);
		}
	}
	else if(msisdn[0] != 0x0)
	{
		if(appName[0] != 0x0 && armedEvent[0] != 0x0 && armedSubEvent[0] != 0x0 && msisdn[0] != 0x0 )
		{
			sprintf(corr, "%s:%s:%s:%s", appName, armedEvent, armedSubEvent, msisdn);
			SFLOG_DEBUG("Output[%s]", corr);
		}
		else if(appName[0] != 0x0 && armedEvent[0] != 0x0 && armedSubEvent[0] == 0x0 && msisdn[0] != 0x0)
		{
			sprintf(corr, "%s:%s:00:%s", appName, armedEvent, msisdn);
			SFLOG_DEBUG("Output[%s]", corr);
		}
		else{
			strcpy(corr,randstring(10));
			SFLOG_DEBUG("Output[%s]", corr);
		}
	}
	if(corr[0] == 0x0)
	{
		strcpy(corr,randstring(10));
		SFLOG_DEBUG("Output[%s]", corr);
	}
    while ((corr[strlen(corr)-1]==10)||(corr[strlen(corr)-1]==13)) corr[strlen(corr)-1] = '\0';
    //!--
	if (bflag==1) free(bdata);
        return 0;
}

int main(int argc, char *argv[])
{
    char *input;
    char output[MAX_CORR];
    input = argv[1];

    if ((argc!=2) || (argv[1]==NULL)) {
        printf("usage: ./test \"input\"\n");
        return 1;
    }

    memset(output, 0, sizeof(output));
    extract_correlate(input, strlen(input), 1, (argv[2])?argv[2]:"test", output, MAX_CORR);

    printf("[%s]\n", output);

    return 0;
}
