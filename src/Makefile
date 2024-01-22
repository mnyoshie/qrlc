CC = gcc
CFLAGS = -O2 -ggdb3
#CFLAGS += -D_FORTIFY_SOURCE=2
CFLAGS += -fpie
#CFLAGS += -fstack-protector
#CFLAGS += -fsanitize=address
CFLAGS += -Wformat -Wformat-security

LDFLAGS = -lstdc++
LDFLAGS += -lm
LDFLAGS += -lcrypto
#LDFLAGS += -lprotobuf-c
LDFLAGS += -lrandomx
LDFLAGS += -lxmss_qrl
LDFLAGS += -lcurl
#LDFLAGS += -fsanitize=address

CSOURCES = qrl.c
CSOURCES += xmssf.c
CSOURCES += utils.c
CSOURCES += log.c
CSOURCES += grpc.c
CSOURCES += protobuf-c.c
CSOURCES += qrl.pb-c.c
CSOURCES += rx-slow-hash.c

COBJECTS = $(patsubst %.c,%.o,$(CSOURCES))

all: a.out

a.out : $(COBJECTS)
	$(CC) -L../xmss-alt $(LDFLAGS) $^ -o $@

$(COBJECTS) : %.o:%.c
	$(CC) -c $(CFLAGS) -I.. $< -o $@
qrl.pb-c.c ../include/qrl.pb-c.h : ../prebuilt/qrl.pb-c.c ../prebuilt/qrl.pb-c.h
	cp ../prebuilt/qrl.pb-c.c .
	cp ../prebuilt/qrl.pb-c.h ./include

clean:
	rm $(COBJECTS) a.out
