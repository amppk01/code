#include "correlate.h"
int runnumber = 1;

int extract_correlate(PDU* pdu, char *buff)
{
	int i, tag;
	char *value;
	
	if(runnumber == 99999){
		runnumber = 1;
	}

	//!correlate logic
	for (i = 0; i < pdu->opt->num; i++)
	{
		value = (char*)pdu->opt->tlv[i].val;
		tag = pdu->opt->tlv[i].tag.s;
		if (tag == DEST_SUBADDRESS)
		{
			if(strlen(value) > 0)
			{
				sprintf(buff,"%s:%s:%05d:ES11", value, time_stamp(), runnumber);
				runnumber++;
				return 0;
			}
		}
	}
	sprintf(buff, "%s", randstring(11));
	return 0;
}