CC = clang
LD = ld.lld

CFLAGS = -O0 
CFLAGS += -ggdb3
CFLAGS += -std=c99
CFLAGS += -D_FORTIFY_SOURCE=2
CFLAGS += -fpie
CFLAGS += -I..
CFLAGS += -fstack-protector
#CFLAGS += -fsanitize=address
CFLAGS += -Wformat
CFLAGS += -Wformat-security
CFLAGS += -Wall
CFLAGS += -Wextra

LDFLAGS = -L$(PREFIX)/lib
LDFLAGS += -L../xmss-alt 
LDFLAGS += -L../randomx

# For Termux
ifeq ($(shell uname -o),Android)
  LDFLAGS += -L/system/lib64
  LDFLAGS += -lc++_shared
  LDFLAGS += -lunwind
  LDFLAGS += -ldl
  LDFLAGS += -dynamic-linker /system/bin/linker64
endif
LDFLAGS += -lc
LDFLAGS += -lm
LDFLAGS += -lstdc++
LDFLAGS += -ljson-c
LDFLAGS += -lcrypto
LDFLAGS += -lleveldb
LDFLAGS += -lrandomx
LDFLAGS += -lxmssf_qrl
#LDFLAGS += -lcurl
#LDFLAGS += -fsanitize=address

csources = log.c
csources += hash.c
csources += chain.c
csources += utils.c
csources += types.c
csources += base64.c
csources += pb2types.c
csources += dev_config.c
#csources += grpc.c
csources += cdecode.c
csources += cencode.c
csources += xmssf.c
csources += qrl.pb-c.c
csources += protobuf-c.c
csources += rx-slow-hash.c

ifeq ($(V),1)
  Q=
else
  Q=@
endif

objects = $(patsubst %.c,%.o,$(csources))

all : libqrlc.a

libqrlc.a : $(objects)
	$(AR) rcs $@ $^

%.o : %.c %.h
	@echo "  CC $<" 
	$(Q)$(CC) -c $(CFLAGS) $< -o $@

%.o : %.c
	@echo "  CC $<" 
	$(Q)$(CC) -c $(CFLAGS) $< -o $@

$(main) : $(objects) $(main).o
	$(CC) $(LDFLAGS) $^ -o $@

ifeq ($(main),)
clean:
	rm $(objects) libqrlc.a
else
clean:
	rm $(objects) libqrlc.a $(main) $(main).o
endif
