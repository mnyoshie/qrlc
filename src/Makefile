# Makefile - Makefile for most linux based systems
# to get rid of cmake builds.

# Written by the QRLC Authors.

#qrlc version draft

#CC = clang

#HACK: link the objects with additional C++ standard libs
LD = $(CXX)

CFLAGS = -O0
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
CFLAGS += -Wno-implicit-fallthrough
CFLAGS += -Wall
CFLAGS += -Wextra

CFLAGS += $(EXTRACFLAGS)
CXXFLAGS += $(EXTRACXXFLAGS)

LDFLAGS = -L$(PREFIX)/lib
LDFLAGS += -L../xmss-alt 
LDFLAGS += -L../randomx
LDFLAGS += -L../cryptonight

# For Termux
ifeq ($(shell uname -o),Android)
  LDFLAGS += -L/system/lib64
  LDFLAGS += -lc++_shared
  LDFLAGS += -lunwind
  LDFLAGS += -ldl
  LDFLAGS += -dynamic-linker /system/bin/linker64
endif
LDFLAGS += -lm
LDFLAGS += -lstdc++
LDFLAGS += -ljson-c
LDFLAGS += -lcrypto
LDFLAGS += -lpthread
LDFLAGS += -lleveldb
LDFLAGS += -lxmssf_qrl
LDFLAGS += -lrandomx
LDFLAGS += -lcryptonight
#LDFLAGS += -fsanitize=address

-include ../config.mk

csources = log.c
csources += hash.c
csources += chain.c
csources += utils.c
csources += types.c
csources += base64.c
csources += license.c
csources += pb2types.c
csources += dev_config.c

csources += cdecode.c
csources += cencode.c
csources += xmssf.c
csources += qrl.pb-c.c
csources += protobuf-c.c
#csources += rx-slow-hash.c

csources += qcore/block.c
csources += qcore/tx.c
csources += qcore/transfer_tx.c
csources += qcore/coinbase_tx.c

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

ifeq ($(machine-endian),little)
  CFLAGS += -DQLITTLE_ENDIAN
endif

ifeq ($(machine-endian),big)
  CFLAGS += -DQBIG_ENDIAN
endif

ifeq ($(feature-bswap),1)
  CFLAGS += -DQHAVE_BSWAP
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


%.bin : %.o libqrlc.a
	$(LD) $< -L. -lqrlc $(LDFLAGS) -o $@

test: main.bin 

clean:
	rm $(objects) libqrlc.a *.bin tests/*.bin || true
