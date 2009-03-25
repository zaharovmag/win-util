CC=gcc
LD=ld
CFLAGS=-Iinclude
LDFLAGS=


all:getfacl srvcchpw

getfacl:getfacl.c lib/win.c
	${CC} ${CFLAGS} ${LDFLAGS} getfacl.c lib/win.c -o $@

srvcchpw:srvcchpw.c
	${CC} ${CFLAGS}	${LDFLAGS} srvcchpw.c -o $@


