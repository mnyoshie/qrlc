CC = clang

CFLAGS = -O2 
CFLAGS += -ggdb3
CFLAGS += -D_FORTIFY_SOURCE=2
CFLAGS += -fpie
#CFLAGS += -fstack-protector
CFLAGS += -fsanitize=address
CFLAGS += -Wformat
CFLAGS += -Wformat-security
CFLAGS += -Wall
CFLAGS += -Wextra

LDFLAGS = -lstdc++
LDFLAGS += -lm
LDFLAGS += -ljson-c
LDFLAGS += -lcrypto
LDFLAGS += -lleveldb
LDFLAGS += -lrandomx
LDFLAGS += -lxmss_qrl
#LDFLAGS += -lcurl
LDFLAGS += -fsanitize=address

CSOURCES = qrl.c
CSOURCES += hash.c
CSOURCES += chain.c
CSOURCES += utils.c
CSOURCES += log.c
CSOURCES += dev_config.c
#CSOURCES += grpc.c
CSOURCES += xmssf.c
CSOURCES += qrl.pb-c.c
CSOURCES += protobuf-c.c
CSOURCES += rx-slow-hash.c

ifeq ($(V),1)
  Q=
else
  Q=@
endif

COBJECTS = $(patsubst %.c,%.o,$(CSOURCES))


qrl : $(COBJECTS)
	$(CC) -L../xmss-alt $(LDFLAGS) $^ -o $@

$(COBJECTS): %.o : %.c
	@echo "  CC $<" 
	$(Q)$(CC) -c $(CFLAGS) -I.. $< -o $@


clean:
	rm $(COBJECTS) qrl
