#include "correlate.h"

void on_element_attrib(char * elename, int attrib_t, char * attrib_val)
{
	SFLOG_DEBUG("%s [%d][%s]", elename, attrib_t, attrib_val);

	if (strcmp("Acct-Session-Id", elename) == 0 )
	{
		strcpy(global_cor, attrib_val);
	}
}

void on_element_attrib_uint(char * elename, int attrib_t, uint attrib_val)
{

}

int af_extract_correlate(RDS_DICT * dict, char * secret, RDS_MSG * msg, char* corr, int max_output)
{
	SFLOG_DEBUG("nothing blah blah blah." );
    return 0;
}

int extract_correlate(RDS_DICT * dict, char * secret, RDS_MSG * msg, char* corr, int max_output)
{
	char error[256];
	global_cor[0] = 0;

	if (msg == NULL) return 1;
	sprintf(error,"%s","Not found");
	if (rds_data_dispatch(dict, NULL, secret, msg->msg, msg->len, &(msg->index.addr), 0, error) == RDS_RET_OK && global_cor[0] != 0)
	{
		int _l = strlen(global_cor);
		if (_l >= max_output)
		{
			global_cor[_l] = 0;
		}
		strcpy(corr, global_cor);
		SFLOG_DEBUG("Output:[%s]", corr);
		return 0;
	}
	else
	{
		SFLOG_ERROR(error);
	}

    return 1;
}
