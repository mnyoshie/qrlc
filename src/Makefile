#CC = clang
#LD = ld.lld

CFLAGS = -Ofast 
CFLAGS += -ggdb3
CFLAGS += -std=c99
CFLAGS += -D_FORTIFY_SOURCE=2
CFLAGS += -fpie
CFLAGS += -I.
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

csources += core/block.c
csources += core/tx.c
csources += core/transfer_tx.c
csources += core/coinbase_tx.c

ifeq ($(V),1)
  Q=
else
  Q=@
endif

machine := $(shell uname -m)
machine := $(shell echo $(machine) | sed -e 's/x86-64/x86_64/' -e 's/amd64/x86_64/' -e 's/i686/x86_64/'\
					-e 's/arm64/aarch64/' -e 's/armv8-a/aarch64/' )

ifeq ($(machine),x86_64)
  CXXFLAGS += -march=native
  CFLAGS += -march=native
endif

ifeq ($(machine),aarch64)
  CXXFLAGS += -march=armv8-a+crypto
  CFLAGS += -march=armv8-a+crypto
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
	$(CC) $^ $(LDFLAGS) -o $@

ifeq ($(main),)
clean:
	rm $(objects) libqrlc.a
else
clean:
	rm $(objects) libqrlc.a $(main) $(main).o
endif
