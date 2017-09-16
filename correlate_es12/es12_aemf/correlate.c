/*
history
1.2.18051027	[Fix] Session="triggerSource:event:userIdData".
1.1.27032017	[Create] correlate Project AEMF 3.
*/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "correlate.h"
#include "sflog.h"

int extract_correlate   (char *ber, int blen, unsigned int flagment, char *filename, char *corr, int max_buffer)
{
    char *bdata, *start_p, *end_p, event[MAX_CORR], triggerSource[MAX_CORR], userIdData[MAX_CORR];
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
	event[0] = 0x0;
	triggerSource[0] = 0x0;
	userIdData[0] = 0x0;
    //!-- get correlation logic
    start_p = bdata;
    if(start_p != NULL)
	{
		start_p = strstr(start_p, "|");
		if(start_p != NULL)
		{
			start_p ++;
			start_p = strstr(start_p, "|");
			if(start_p != NULL)
			{
				start_p ++;
				end_p = strstr(start_p, "|");
				if(end_p != NULL)
				{
					len = (end_p - start_p);
					if(len > 0 )
					{
						int i = 1; // userIdData = 1 char
						if(len >= i){
							start_p += (len-i);
							len = (end_p - start_p);
							strncpy(userIdData, start_p, len);
							userIdData[len] = 0x0;
						}else{
							SFLOG_DEBUG("userIdData is invalid");
						}
					}
				}
				start_p ++;
				start_p = strstr(start_p, "|");
				if(start_p != NULL)
				{
					start_p ++;
					end_p = strstr(start_p, "|");
					
					if(end_p != NULL)
					{
						len = (end_p - start_p);
						if(len > 0 )
						{
							memcpy(triggerSource, start_p, len);
							triggerSource[len] = 0x0;
						}
					}
					start_p ++;
					start_p = strstr(start_p, "|");
					if(start_p != NULL)
					{
						start_p ++;
						end_p = strstr(start_p, "|");
						
						if(end_p != NULL)
						{
							len = (end_p - start_p);
							if(len > 0 )
							{
								memcpy(event, start_p, len);
								event[len] = 0x0;
							}
						}
					}
				}
			}
		}
	}
	if(triggerSource[0] != 0x0 && event[0] != 0x0 && userIdData[0] != 0x0)
	{
		sprintf(corr, "%s:%s:%s", triggerSource, event, userIdData);
		SFLOG_DEBUG("Output[%s]", corr);
	}
	else{
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
