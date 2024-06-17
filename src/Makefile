# Makefile - Makefile for most linux based systems
# to get rid of cmake builds.

# Written by the QRLC Authors.

#qrlc version draft

-include ../config.mk
#HACK: To link the objects with additional C++ standard libs
LD = $(CXX)

CFLAGS = -std=c99
CFLAGS += -D_FORTIFY_SOURCE=2
CFLAGS += -fpie
CFLAGS += -I.
CFLAGS += -I..
CFLAGS += -fstack-protector
CFLAGS += -Wformat
CFLAGS += -Wformat-security
CFLAGS += -Wno-implicit-fallthrough
CFLAGS += -Wall
CFLAGS += -Wextra

ifeq ($(DEBUG),1)
  CFLAGS += -O0
  CFLAGS += -ggdb3
  CFLAGS += -fsanitize=address
  CFLAGS += -fsanitize=undefined
  CFLAGS += -DQDEBUG=1
else
  CFLAGS += -O3
endif

CFLAGS += $(EXTRACFLAGS)
CXXFLAGS += $(EXTRACXXFLAGS)

LDFLAGS = -L$(PREFIX)/lib
#LDFLAGS += -L../xmss-alt 
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
#LDFLAGS += -lxmssf_qrl
LDFLAGS += -lrandomx
LDFLAGS += -lcryptonight
LDFLAGS += -fsanitize=address


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
csources += xmss.c
csources += qrl.pb-c.c
csources += protobuf-c.c
#csources += rx-slow-hash.c

csources += qcore/block.c
csources += qcore/tx.c
csources += qcore/transfer_tx.c
csources += qcore/coinbase_tx.c
csources += qcore/message_tx.c
csources += qcore/latticepk_tx.c

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

test: tests/eget_block_by_number_req.bin tests/dget_block_by_number_resp.bin tests/gen_key.bin tests/sign_msg.bin
	@bash -c 'for i in 0 1 2 15 902375 90231 2999079; do \
		echo "##############################################################################"; \
		printf "##########################> \e[1;96mBLOCK %016x\e[0m <##########################\n" $$i; \
		tests/eget_block_by_number_req.bin $$i | curl \
		--http2-prior-knowledge \
		-H "te: trailers" \
		-H "content-type: application/grpc" \
		--data-binary @- \
		mainnet-1.automated.theqrl.org:19009/qrl.PublicAPI/GetBlockByNumber | tests/dget_block_by_number_resp.bin	; done'
	./tests/gen_key.bin
	./tests/sign_msg.bin
	@echo libqrlc: OK


clean:
	rm $(objects) libqrlc.a *.bin tests/*.bin tests/*.o || true
