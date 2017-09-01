#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include "dmp.h"
#include "sflib.h"
#include "sflog.h"

enum CORR_RET
{
   CORR_RET_ERROR = -1,
   CORR_RET_UNKNOWN = 0,
   CORR_RET_AVP,
   CORR_RET_STRING,
};

//#define SUBSCRIPTION_DATA_SIZE						51
#define SUBSCRIPTION_DATA_SIZE						256

#define NEED_SUBSCRIPTION_ID_TYPE					0

#define DMP_AVP_CODE_SESSION_ID						263
#define DMP_AVP_CODE_SUBSCRIPTION_ID				443
#define DMP_AVP_CODE_SUBSCRIPTION_ID_DATA			444
#define DMP_AVP_CODE_SUBSCRIPTION_ID_TYPE			450

int extract_correlate (DMP_DICT *dmp_dict, int *avp_code, DMP_AVP **avp, int avp_count, char *new_session);
