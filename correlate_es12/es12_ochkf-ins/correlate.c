#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include "correlate.h"
#include "sflib.h"
#include "sflog.h"

int extract_correlate (char *ber, int blen, unsigned int flagment, char *filename, char *corr, int max_buffer)
{
    char *bdata, *start_p, *end_p;
	char *msisdn, *currentState, *counterId, *previousState, *nextState, *amfActiveStopTime, *amfSuspendStopTime, *amfDisableStopTime, *amfTerminateStopTime, *productOffer, *activationDate, *expiryTime;
    char bflag = 0;
	int key;
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
    if(strstr(bdata,"NotifyBeforeStateChangeRequest") != NULL)
	{
		start_p = strstr(bdata, "Data");
		if(start_p != NULL)
		{
			start_p = strstr(start_p+4, "=");
			if(start_p != NULL)
			{
				//comma 1
				start_p++;
				end_p = strstr(start_p, ",");
				key = (end_p - start_p);
				msisdn = start_p;
				msisdn[key] = 0x0;
				
				//comma 2
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				
				//comma 3
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				key = (end_p - start_p);
				currentState = start_p;
				currentState[key] = 0x0;
				
				//comma 4
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				key = (end_p - start_p);
				nextState = start_p;
				nextState[key] = 0x0;
				
				//comma 5
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				
				//comma 6
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				key = (end_p - start_p);
				amfActiveStopTime = start_p;				
				amfActiveStopTime[key] = 0x0;
				
				//comma 7
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				key = (end_p - start_p);
				amfSuspendStopTime = start_p;
				amfSuspendStopTime[key] = 0x0;
				
				//comma 8
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				key = (end_p - start_p);
				amfDisableStopTime = start_p;
				amfDisableStopTime[key] = 0x0;
				
				//comma 9
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				key = (end_p - start_p);
				amfTerminateStopTime = start_p;
				amfTerminateStopTime[key] = 0x0;
				
				sprintf(corr, "%s|%s|%s|%s|%s|%s|%s", msisdn, currentState, nextState, amfActiveStopTime, amfSuspendStopTime, amfDisableStopTime, amfTerminateStopTime);
				SFLOG_DEBUG("Output:[%s]", corr);
			}
		}
		else
		{
			if (bflag==1) free(bdata);
			return -1;
		}
	}
	else if(strstr(bdata,"StateChangeRequest") != NULL)
	{
		start_p = strstr(bdata, "Data");
		if(start_p != NULL)
		{
			start_p = strstr(start_p+4, "=");
			if(start_p != NULL)
			{
				//comma 1
				start_p++;
				end_p = strstr(start_p, ",");
				key = (end_p - start_p);
				msisdn = start_p;
				msisdn[key] = 0x0;
				
				//comma 2
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				
				//comma 3
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				
				//comma 4
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				
				//comma 5
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				
				//comma 6
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				key = (end_p - start_p);
				currentState = start_p;
				currentState[key] = 0x0;
				
				//comma 7
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				key = (end_p - start_p);
				previousState = start_p;
				previousState[key] = 0x0;
				
				//comma 8
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				
				//comma 9
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				
				//comma 10
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				
				//comma 11
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				
				//comma 12
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				
				//comma 13
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				key = (end_p - start_p);
				amfActiveStopTime = start_p;
				amfActiveStopTime[key] = 0x0;
				
				//comma 14
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				key = (end_p - start_p);
				amfSuspendStopTime = start_p;
				amfSuspendStopTime[key] = 0x0;
				
				//comma 15
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				key = (end_p - start_p);
				amfDisableStopTime = start_p;
				amfDisableStopTime[key] = 0x0;
				
				//comma 16
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				key = (end_p - start_p);
				amfTerminateStopTime = start_p;
				amfTerminateStopTime[key] = 0x0;
				
				
				sprintf(corr, "%s|%s|%s|%s|%s|%s|%s", msisdn, currentState, previousState, amfActiveStopTime, amfSuspendStopTime, amfDisableStopTime, amfTerminateStopTime);
				SFLOG_DEBUG("Output:[%s]", corr);
			}
		}
		else
		{
			if (bflag==1) free(bdata);
			return -1;
		}
	
	}
    else if(strstr(bdata,"DeleteAfterTerminateRequest") != NULL)
	{
		start_p = strstr(bdata, "Data");
		if(start_p != NULL)
		{
			start_p = strstr(start_p+4, "=");
			if(start_p != NULL)
			{
				//comma 1
				start_p++;
				end_p = strstr(start_p, ",");
				key = (end_p - start_p);
				msisdn = start_p;
				msisdn[key] = 0x0;
				
				//comma 2
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				
				//comma 3
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				key = (end_p - start_p);
				currentState = start_p;
				currentState[key] = 0x0;
				
				//comma 4
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				
				//comma 5
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				
				//comma 6
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				key = (end_p - start_p);
				amfActiveStopTime = start_p;
				amfActiveStopTime[key] = 0x0;
				
				//comma 7
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				key = (end_p - start_p);
				amfSuspendStopTime = start_p;
				amfSuspendStopTime[key] = 0x0;
				
				//comma 8
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				key = (end_p - start_p);
				amfDisableStopTime = start_p;
				amfDisableStopTime[key] = 0x0;
				
				//comma 9
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				key = (end_p - start_p);
				amfTerminateStopTime = start_p;
				amfTerminateStopTime[key] = 0x0;
				
				sprintf(corr, "%s|%s|%s|%s|%s|%s", msisdn, currentState, amfActiveStopTime, amfSuspendStopTime, amfDisableStopTime, amfTerminateStopTime);
				SFLOG_DEBUG("Output:[%s]", corr);
			}
		}
		else
		{
			if (bflag==1) free(bdata);
			return -1;
		}
	}
	else if(strstr(bdata,"DeleteRewardPackageRequest") != NULL)
	{
		start_p = strstr(bdata, "Data");
		if(start_p != NULL)
		{
			start_p = strstr(start_p+4, "=");
			if(start_p != NULL)
			{
				//comma 1
				start_p++;
				end_p = strstr(start_p, ",");
				key = (end_p - start_p);
				msisdn = start_p;
				msisdn[key] = 0x0;
				
				//comma 2
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				
				//comma 3
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				
				//comma 4
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				key = (end_p - start_p);
				counterId = start_p;
				counterId[key] = 0x0;
				
				//comma 5
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				
				//comma 6
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				key = (end_p - start_p);
				expiryTime = start_p;
				expiryTime[key] = 0x0;
				
				//comma 7
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				key = (end_p - start_p);
				productOffer = start_p;
				productOffer[key] = 0x0;
				
				//comma 8
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				
				//comma 9
				end_p++;
				start_p = end_p;
				end_p = strstr(start_p, ",");
				key = (end_p - start_p);
				activationDate = start_p;
				activationDate[key] = 0x0;
				
				sprintf(corr, "%s|%s|%s|%s|%s", msisdn, counterId, productOffer, activationDate, expiryTime);
				SFLOG_DEBUG("Output:[%s]", corr);
			}
		} 
		else 
		{
			if (bflag==1) free(bdata);
			return -1;
		}
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
