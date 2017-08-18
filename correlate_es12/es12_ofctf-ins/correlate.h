#define MAX_CORR    128
//ber is the bulk of data to extract
//blen is length of ber
//corr is key of hash
int extract_correlate (char *ber, int blen, unsigned int flagment, char *filename, char *corr, int max_buffer);
