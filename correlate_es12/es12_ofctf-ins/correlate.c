#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "correlate.h"
#include "sflib.h"
#include "sflog.h"

int extract_correlate (char *ber, int blen, unsigned int flagment, char *filename, char *corr, int max_buffer)
{
    char *bdata, *start_p, *end_p;
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
				start_p = strstr(start_p, "|");
				if(start_p != NULL)
				{
					start_p ++;
					start_p = strstr(start_p, "|");
					if(start_p != NULL)
					{
						start_p ++;
						end_p = strstr(start_p, "|");
						
						len = (end_p - start_p);
						if(len > 0 )
						{
							if(len < max_buffer - 1)
							{
								memcpy(corr, start_p, len);
								corr[len] = 0x0;
								SFLOG_DEBUG("Output:[%s]", corr);
							}
							else
							{
								memcpy(corr, start_p, max_buffer - 1);
								corr[max_buffer-1] = 0x0;
								SFLOG_DEBUG("Output:[%s]", corr);
							}
						} else {
							return 1;
						}
					}else {
						return 1;
					}
				}else {
					return 1;
				}
			}else {
				return 1;
			}	
		}else {
			return 1;
		}
	}
	else {
        if (bflag==1) free(bdata);
        return -1;
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
