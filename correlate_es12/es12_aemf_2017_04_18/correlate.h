#define MAX_CORR    128
//ber is the bulk of data to extract
//blen is length of ber
//corr is key of hash
int extract_correlate (char *ber, int blen, unsigned int flagment, char *filename, char *corr, int max_buffer);

char *randstring(size_t length)
{
	static char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	char *randomString = NULL;
	if (length)
	{
		randomString = malloc(length +1);
		if (randomString) {
			int key, n, l = (int) (sizeof(charset) -1);
			for (n = 0;n < length;n++)
			{
				key = rand() % l;
				randomString[n] = charset[key];
			}
			randomString[length] = '\0';
		}
	}
	return randomString;
}