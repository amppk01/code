/*
history
1.2.12092017	[Add] Check avp User-Name.
1.1.04092017	[Create] correlate Project LTC-DGW.
*/
#include "correlate.h"

static int
get_subscription_id(DMP_AVP **avp, int avp_count, int *id_type, char *id_data)
{
	int i;
	int n;
	char *p;
	
	for (i = 0; i < avp_count; ++i)
	{
		SFLOG_DEBUG("nested avp code [%d][%d]", DMP_avp_get_code(avp[i]), DMP_avp_get_type(avp[i]));
		if ((DMP_avp_get_code(avp[i]) == DMP_AVP_CODE_SUBSCRIPTION_ID_TYPE))	
		//&&(DMP_avp_get_type(avp[i]) == DMP_AVP_TYPE_ENUMERATED))
		{
			*id_type = DMP_avp_get_int32(avp[i]);
		}
		else if ((DMP_avp_get_code(avp[i]) == DMP_AVP_CODE_SUBSCRIPTION_ID_DATA)&&
				 (DMP_avp_get_type(avp[i]) == DMP_AVP_TYPE_UTF8STRING))
		{
			n = DMP_avp_get_data(avp[i], &p);
			if (n >= SUBSCRIPTION_DATA_SIZE)
			{
				SFLOG_ERROR("Subscription data length exceeds [%d]", n);
				return -1;
			}
			memcpy(id_data, p, n);
			id_data[n] = '\0';
		}
	}
	return 0;
}

static int
get_avp_data(DMP_DICT *dmp_dict, DMP_AVP **avp, int avp_count, char *id_data)
{
	DMP_AVP **aa;
	char err[1024], *p, *start_p, *end_p;
	int i, id_type=-1, n, len, avp_code=0;

	for (i = 0; i < avp_count; ++i){
		SFLOG_DEBUG("avp code [%d][%d]", DMP_avp_get_code(avp[i]), DMP_avp_get_type(avp[i]));
		if (DMP_avp_get_type(avp[i]) == DMP_AVP_TYPE_GROUPED)
		{
			avp_code = DMP_avp_get_code(avp[i]);
			if (avp_code == DMP_AVP_CODE_SUBSCRIPTION_ID)
			{
				if (DMP_avp_get_nested_avp(dmp_dict, 0, avp[i], &aa, &n, err) != 0)
				{
					SFLOG_ERROR("DMP_avp_get_nested_avp return error [%s]", err);
					return -1;
				}
				if (get_subscription_id(aa, n, &id_type, id_data) != 0)
				{
					SFLOG_ERROR("get_subscription_id return error");
					return -1;
				}
				SFLOG_DEBUG("ID Type [%d] ID Data [%s]", id_type, id_data);
			}
			if (id_type == 0) break;
		}
		
		if(DMP_avp_get_type(avp[i]) == DMP_AVP_TYPE_UTF8STRING)
		{
			avp_code = DMP_avp_get_code(avp[i]);
			if(avp_code == DMP_AVP_CODE_USER_NAME)
			{
				n = DMP_avp_get_data(avp[i], &p);
				if (n >= USER_NAME_SIZE)
				{
					SFLOG_ERROR("User-Name length exceeds [%d]", n);
					return -1;
				}
				start_p = strstr(p, "msisdn");
				if(start_p != NULL)
				{
					start_p += 6;
					end_p = strstr(start_p, ".ais.co.th");
					if(end_p != NULL)
					{
						len = (end_p - start_p);
						if((len) > 0 && len < MAX_CORR)
						{
							strncpy(id_data, start_p, len);
							id_data[len] = 0x0;
							SFLOG_DEBUG(" ID Data [%s]", id_data);
							return 0;
						}
						else {
							return -1;
						}
					}
					else {
						return -1;
					}
				}
				else {
					return -1;
				}
			}
		}
	}
	if (avp_code == DMP_AVP_CODE_SUBSCRIPTION_ID){
		if ((id_type!=0)){
			return -1;
		}else{
			return 0;
		}
	}else if(avp_code == DMP_AVP_CODE_USER_NAME){
		return 0;
	}
	else {
		return -1;
	}
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
