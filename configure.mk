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

err=0
ifeq ($(V),1)
  Q=
else
  Q=@
  tonull=>/dev/null 2>/dev/null
endif

check-c-feature = $(shell $(CC) $(CFLAGS) tests/$(1).c $(2) -o tests/$(1)c.bin $(tonull) && echo 1 || echo 0)
check-cxx-feature = $(shell $(CXX) $(CXXFLAGS) tests/$(1).cpp $(2) -o tests/$(1)cxx.bin $(tonull) && echo 1 || echo 0)
check-compiler-feature = $(shell $(CC) -m$(1) -dM -E - < /dev/null 2>/dev/null | grep $(2) >/dev/null && echo 1 || echo 0)
check-cpu-feature = $(shell cat /proc/cpuinfo | grep $(1) > /dev/null && echo 1 || echo 0)

machine := $(shell uname -m)
define get-machine
machine := $(shell echo $(machine) | sed -e 's/x86-64/x86_64/' -e 's/amd64/x86_64/' \
					-e 's/arm64/aarch64/' -e 's/armv8-a/aarch64/' )
endef

define get-machine-endian
machine-endian := $(shell ./tests/endianc.bin || echo unknown)
endef

define test-cpu-feature
cpu-feature-$(1) := $(call check-cpu-feature,$(1),$(2))
endef

define test-compiler-feature
compiler-feature-$(1) := $(call check-compiler-feature,$(1),$(2))
endef

define test-c-feature
feature-$(1) := $(call check-c-feature,$(1),$(2))
endef

define test-cxx-feature
feature-$(1) := $(call check-cxx-feature,$(1),$(2))
endef


$(shell echo Configuring... may take a minute >&2)

# XXX: test C compiler
$(info checking for CC compiler)
ifneq ($(call check-c-feature,sane),1)
  $(error What C compiler is even this? CC=$(CC))
endif

# XXX: test CXX compiler
$(info checking for CXX compiler)
ifneq ($(call check-cxx-feature,sane),1)
  $(error What CXX compiler is even this? CXX=$(CXX))
endif


# Tests for various dependencies
$(info checking for libleveldb)
ifneq ($(call check-c-feature,leveldb,-lleveldb),1)
  $(info CANNOT FIND libleveldb)
  missing-deps+=libleveldb
  err=1
endif

$(info checking for libjson-c)
ifneq ($(call check-c-feature,json-c,-ljson-c),1)
  $(info CANNOT FIND libjson-c)
  missing-deps+=libjson-c
  err=1
endif

$(info checking for libcrypto)
ifneq ($(call check-c-feature,crypto,-lcrypto),1)
  $(info CANNOT FIND libcrypto)
  missing-deps+=libcrypto
  err=1
endif

$(info checking for boost headers)
ifneq ($(call check-cxx-feature,boost),1)
  $(info CANNOT FIND boost headers)
  missing-deps+=boost
  err=1
endif

ifneq ($(call check-c-feature,endian),1)
  $(error insane environment)
endif

ifeq ($(err),1)
  $(error Needed dependencies: $(missing-deps))
endif

$(eval $(call test-cpu-feature,ssse3))
$(eval $(call test-cpu-feature,avx2))
$(eval $(call test-compiler-feature,ssse3,__SSSE3__))
$(eval $(call test-compiler-feature,avx2,__AVX2__))

all:
	@[ $(err) -eq 1 ] && false || true
	echo '$(call get-machine)' > config.mk
	echo '$(call get-machine-endian)' >> config.mk
	echo '$(call test-cxx-feature,atomic)' >> config.mk
	echo '$(call test-cxx-feature,hwcap)' >> config.mk
	echo '$(call test-c-feature,bswap)' >> config.mk
	echo 'feature-avx2 := $(shell [ $(cpu-feature-avx2) -eq 1 ] && [ $(compiler-feature-avx2) -eq 1 ] && echo 1 || echo 0)' >> config.mk
	echo 'feature-ssse3 := $(shell [ $(cpu-feature-ssse3) -eq 1 ] && [ $(compiler-feature-ssse3) -eq 1 ] && echo 1 || echo 0)' >> config.mk

