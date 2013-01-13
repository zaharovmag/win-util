CC=cl
LD=ld
CFLAGS=-Iinclude -Zi
LDFLAGS=Advapi32.lib



all:getfacl srvcchpw

getfacl:getfacl.c lib/win.c
	$(CC) $(CFLAGS) $(LDFLAGS) getfacl.c lib/win.c  

srvcchpw:srvcchpw.c
	$(CC) $(CFLAGS)	$(LDFLAGS) srvcchpw.c lib/getopt.c


