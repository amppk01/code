/*
history
1.1.29032017	[Create] correlate Project AMF_TM.
*/

#include "correlate.h"
int runnumber = 1;

static int
get_session_id(DMP_AVP **avp, int avp_count, int *id_type, char *id_data)
{
	int i;
	
	if(runnumber == 99999){
		runnumber = 1;
	}
	for (i = 0; i < avp_count; ++i)
	{
		//SFLOG_DEBUG("nested avp code [%d][%d]", DMP_avp_get_code(avp[i]), DMP_avp_get_type(avp[i]));
		if ((DMP_avp_get_code(avp[i]) == DMP_AVP_CODE_SESSION_ID)&&
			(DMP_avp_get_type(avp[i]) == DMP_AVP_TYPE_UTF8STRING))
		{
			//int n;
			char *p;
			*id_type = DMP_avp_get_int32(avp[i]);
			//n = DMP_avp_get_data(avp[i], &p);
			DMP_avp_get_data(avp[i], &p);
			
			sprintf(p,"%s|%05d",p, runnumber);
			runnumber++;
			memcpy(id_data, p, strlen(p));
			id_data[strlen(p)] = '\0';
		}
	}
	return 0;
}

static int
get_avp_data(DMP_DICT *dmp_dict, DMP_AVP **avp, int avp_count, char *id_data)
{
	int i, id_type=-1;

	for (i = 0; i < avp_count; ++i)
	{
		//SFLOG_DEBUG("avp code [%d][%d]", DMP_avp_get_code(avp[i]), DMP_avp_get_type(avp[i]));
		if (DMP_avp_get_type(avp[i]) == DMP_AVP_TYPE_UTF8STRING)
		{
			//DMP_AVP **aa;
			//char err[1024];
			//int n, avp_code;
			
			//avp_code = DMP_avp_get_code(avp[i]);
			if (DMP_avp_get_code(avp[i]) == DMP_AVP_CODE_SESSION_ID)
			{
				if (get_session_id(avp, avp_count, &id_type, id_data) != 0)
				{
					SFLOG_ERROR("get_toro_subscription_id return error");
					return -1;
				}
				//SFLOG_DEBUG("ID Type [%d] ID Data [%s]", id_type, id_data);
			}
			if (id_type==0) break;
		}
	}
	//if ((id_type!=0)&&(id_type!=1)) return -1;
	return 0;
}

int extract_correlate (DMP_DICT *dmp_dict, int *avp_code, DMP_AVP **avp_in, int avp_count, char *new_session)
{
///////////////// Use of AVP Code /////////////////
//	(*avp_code) = 457;
//	return CORR_RET_AVP;
////////////////// Use of String //////////////////
//	strcpy(new_session, "My Session");
//	return CORR_RET_STRING;

	if (get_avp_data(dmp_dict, avp_in, avp_count, new_session) != 0)
	{
		(*avp_code) = DMP_AVP_CODE_SESSION_ID;
		return CORR_RET_AVP;
	}
	else
	{
		return CORR_RET_STRING;
	}
}