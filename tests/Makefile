# Makefile - Makefile for most linux based systems
# to get rid of cmake builds.

# Written by the QRLC Authors.

# this is done for environment tests.
# Kinda like ./confgure but hand written

#CC = clang
#LD = ld.lld

CFLAGS = -std=c99
CFLAGS += -D_FORTIFY_SOURCE=2
CFLAGS += -fpie
CFLAGS += -I.
CFLAGS += -I..
CFLAGS += -fstack-protector
CFLAGS += -w

ifeq ($(V),1)
  Q=
else
  Q=@
  tonull=>/dev/null 2>/dev/null
endif

ctest-feature = $(shell $(CC) $(CFLAGS) $(1).c $(2) -o $(1)c.bin $(tonull) && echo 1 || echo 0)
cxxtest-feature = $(shell $(CXX) $(CXXFLAGS) $(1).cpp $(2) -o $(1)cxx.bin $(tonull) && echo 1 || echo 0)

feature = sane
feature += bswap
feature += leveldb
feature += json-c

$(shell echo Configuring... may take a minute >&2)
$(shell rm config.h 2>/dev/null)

ifneq ($(call ctest-feature,sane),1)
  $(error What C compiler is even this? CC=$(CC))
endif

ifneq ($(call cxxtest-feature,sane),1)
  $(error What CXX compiler is even this? CXX=$(CXX))
endif

ifeq ($(call ctest-feature,bswap),1)
  $(file >>config.h,#define QHAVE_BSWAP)
endif

ifneq ($(call ctest-feature,leveldb,-lleveldb),1)
$(shell echo CANNOT FIND libleveldb >&2)
err=1
endif

ifneq ($(call ctest-feature,json-c,-ljson-c),1)
$(shell echo CANNOT FIND libjson-c >&2)
err=1
endif

ifneq ($(call ctest-feature,crypto,-lcrypto),1)
$(shell echo CANNOT FIND libcrypto >&2)
err=1
endif

ifneq ($(call ctest-feature,endian),1)
  $(error insane environment)
endif

ifeq ($(shell ./endianc.bin; echo $$?),2)
  $(file >>config.h,#define QLITTLE_ENDIAN)
else
  ifeq ($(shell ./endianc.bin; echo $$?),3)
    $(file >>config.h,#define QBIG_ENDIAN)
  else
    $(error insane environment)
  endif
endif

ifeq ($(err),1)
  $(error TESTS FAILED)
endif

bins = $(patsubst %.c,%.bin,$(feature))

all :
	mv config.h ../include
	@echo include/config.h generated

clean:
	rm *.bin ../include/config.h config.h || true
