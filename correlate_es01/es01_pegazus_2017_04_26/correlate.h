#define MAX_CORR    256
//ber is the bulk of data to extract
//blen is length of ber
//corr is key of hash

enum return_code
{
    CORR_SUCCESS = 0,
    CORR_DEFAULT,
    CORR_SKIP_MESSAGE,
    CORR_LAST_SESSION
};

int extract_correlate (char *ber, int blen, char *corr);
