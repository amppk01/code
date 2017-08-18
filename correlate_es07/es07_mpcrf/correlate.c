#include "correlate.h"

static int
get_subscription_id(DMP_AVP **avp, int avp_count, int *id_type, char *id_data)
{
	static char func[] = "get_subscription_id";
	int i;

	for (i = 0; i < avp_count; ++i)
	{
		SFLOG_DEBUG((B, "nested avp code [%d][%d]", DMP_avp_get_code(avp[i]), DMP_avp_get_type(avp[i])))
		if ((DMP_avp_get_code(avp[i]) == DMP_AVP_CODE_SUBSCRIPTION_ID_TYPE)&&
			(DMP_avp_get_type(avp[i]) == DMP_AVP_TYPE_ENUMERATED))
		{
			*id_type = DMP_avp_get_int32(avp[i]);
			SFLOG_ERROR((B, "id_type [%s]", id_type))
		}
		else if ((DMP_avp_get_code(avp[i]) == DMP_AVP_CODE_SUBSCRIPTION_ID_DATA)&&
				 (DMP_avp_get_type(avp[i]) == DMP_AVP_TYPE_UTF8STRING))
		{
			int n;
			char *p;
			
			n = DMP_avp_get_data(avp[i], &p);
			SFLOG_ERROR((B, "n [%d]", n))
			if (n >= SUBSCRIPTION_DATA_SIZE)
			{
				SFLOG_ERROR((B, "Subscription data length exceeds [%d]", n))
				return -1;
			}
			/*if((DMP_avp_get_code(avp[i]) == NEED_SUBSCRIPTION_ID_TYPE)
			{
				
			}*/
			memcpy(id_data, p, n);
			id_data[n] = '\0';
		}
	}
	return 0;
}

static int
get_avp_data(DMP_DICT *dmp_dict, DMP_AVP **avp, int avp_count, char *id_data)
{
	static char func[] = "get_avp_data";
	int i, id_type=-1;

	for (i = 0; i < avp_count; ++i)
	{
		SFLOG_DEBUG((B, "avp code [%d][%d]", DMP_avp_get_code(avp[i]), DMP_avp_get_type(avp[i])))
		if (DMP_avp_get_type(avp[i]) == DMP_AVP_TYPE_GROUPED)
		{
			DMP_AVP **aa;
			char err[1024];
			int n, avp_code;
			
			avp_code = DMP_avp_get_code(avp[i]);
			if (avp_code == DMP_AVP_CODE_SUBSCRIPTION_ID)
			{
				if (DMP_avp_get_nested_avp(dmp_dict, 0, avp[i], &aa, &n, err) != 0)
				{
					SFLOG_ERROR((B, "DMP_avp_get_nested_avp return error [%s]", err))
					return -1;
				}
				if (get_subscription_id(aa, n, &id_type, id_data) != 0)
				{
					SFLOG_ERROR((B, "get_subscription_id return error"))
					return -1;
				}
				//SFLOG_DEBUG((B, "ID Type [%d] ID Data [%s]", id_type, id_data))
			}
			if (id_type==0) break;
		}
	}
	
	if ((id_type!=0)&&(id_type!=1)) return -1;
	
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
