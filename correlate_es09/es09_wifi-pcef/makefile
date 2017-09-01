## Define MACROS ##
all: ES09 corr

include ../makefile_ES.defs

## Gather all flag and libs ##
PROJ_CCFLAG=$(STD_CCFLAG) $(INCLUDE_CCFLAG) $(SF_CCFLAG) $(SFCONFIG_CCFLAG) $(XTHREAD_CCFLAG) $(RDS_CCFLAG) $(BASE64_CCFLAG) $(MD5_CCFLAG) -I. 
PROJ_EXEFLAG=$(STD_EXEFLAG)
PROJ_EXELIB=$(STD_EXELIB) $(SF_EXELIB) $(SFCONFIG_EXELIB) $(XTHREAD_EXELIB) $(RDS_EXELIB) $(BASE64_EXELIB) $(MD5_EXELIB) -ldl -rdynamic


clean:
	rm -f *.a *.o

.c.o:
	$(CC) $(PROJ_CCFLAG) -c $< -o $@

ES09: ES09.o
	echo "char build_timestamp[] = \"@(#$@) Last build time -> `date`\";" > buildident.c
	$(CC) $(PROJ_EXEFLAG) -c buildident.c
	$(CC) $(PROJ_EXEFLAG) -o ES09 ES09.o buildident.o $(PROJ_EXELIB)
	rm buildident.*
	
corr:
	$(CC) $(PROJ_CCFLAG) -c correlate.c
	ld -G correlate.o -o lib_es09_correlate.so