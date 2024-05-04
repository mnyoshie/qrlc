# Makefile - Makefile for most linux based systems
# to get rid of cmake builds.

# Written by the QRLC Authors. Inspired from the Linux 
# kernel Makefile

#cryptonight https://github.com/monero-project/monero/tree/2844b5b8dbcfcfe4b3c9dbdf2d16ce2955b13665 (commit from year 2021)


CFLAGS += -O2 -std=gnu11 -fPIE -I./include -I../randomx
CXXFLAGS += -O2 -std=gnu++11 -fPIE -I./include -I../ramdomx

csources += $(directory)aesb.c
csources += $(directory)src/memwipe.c
csources += $(directory)rx-slow-hash.c
csources += $(directory)CryptonightR_JIT.c
csources += $(directory)blake256.c
csources += $(directory)chacha.c
csources += $(directory)groestl.c
csources += $(directory)hash-extra-blake.c
csources += $(directory)hash-extra-groestl.c
csources += $(directory)hash-extra-jh.c
csources += $(directory)hash-extra-skein.c
csources += $(directory)hash.c
csources += $(directory)jh.c
csources += $(directory)keccak.c
csources += $(directory)oaes_lib.c
csources += $(directory)random.c
csources += $(directory)skein.c
csources += $(directory)slow-hash.c
csources += $(directory)tree-hash.c

testall = extra-blake extra-groestl extra-jh extra-skein fast slow-1 slow-2 slow tree

feature-check = $(shell $(CXX) $(CXXFLAGS) tests/$(1).cpp -o tests/$(1)_test.bin $(tonull) && echo 1 || echo 0)
check-cpu-feature = $(shell cat /proc/cpuinfo | grep $(1) > /dev/null && echo 1 || echo 0)
check-compiler-feature = $(shell $(CC) $(2) -dM -E - < /dev/null  | grep $(1) > /dev/null && echo 1 || echo 0)

ifeq ($(V),1)
  Q=
else
  tonull=>/dev/null 2>/dev/null
  Q=@
endif

machine := $(shell uname -m)
machine := $(shell echo $(machine) | sed -e 's/x86-64/x86_64/' -e 's/amd64/x86_64/' \
					-e 's/arm64/aarch64/' -e 's/armv8-a/aarch64/' )

#####################################
#####################################


ifeq ($(call feature-check,atomic),1)
  CXXFLAGS += -DHAVE_CXX_ATOMICS
endif

ifeq ($(call feature-check,hwcap),1)
  CXXFLAGS += -DHAVE_HWCAP
endif

ifeq ($(machine),x86_64)
  CXXFLAGS += -march=native
  CFLAGS += -march=native
  CFLAGS += -maes
  asms = CryptonightR_template.S

  # HAVE cpuid
#  ifeq ($(call check-cpu-feature,cpuid),1)
#  CXXFLAGS += -DHAVE_CPUID
#  CFLAGS += -DHAVE_CPUID
#  endif
  
  # HAVE SSSE3 
  ifeq ($(call check-compiler-feature,__SSSE3__,-mssse3),1)
  CXXFLAGS += -mssse3
  CFLAGS += -mssse3
  endif
  
  # HAVE AVX2
  ifeq ($(call check-compiler-feature,__AVX2__,-mavx2),1)
  CXXFLAGS += -mavx2
  CFLAGS += -mavx2
  endif
endif

ifeq ($(machine),aarch64)
  CXXFLAGS += -march=armv8-a+crypto
  CFLAGS += -march=armv8-a+crypto
endif

CXXFLAGS += $(EXTRACXXFLAGS)
CFLAGS += $(EXTRACFLAGS)

ifeq ($(machine),riscv64)
endif

#####################################
#####################################

objects = $(patsubst %.cpp,%.o,$(cxxsources)) $(patsubst %.c,%.o,$(csources)) $(patsubst %.S,%.o,$(asms))

target : libcryptonight.a

libcryptonight.a : $(objects)
	$(AR) rcs $@ $^

%.o : %.cpp
	@echo "  CXX $< $@"
	$(Q)$(CXX) -c $(CXXFLAGS) $< -o $@

%.o : %.S
	@echo "  CC $< $@"
	$(Q)$(CC) -c $(CFLAGS) $< -o $@

%.o : %.c
	@echo "  CC $< $@"
	$(Q)$(CC) -c $(CFLAGS) $< -o $@

%.bin: %.o libcryptonight.a
	$(CXX) $< -L. -lcryptonight -L../randomx -lrandomx -lpthread -o $@

test: tests/main.bin
	@bash -c ' \
	result=0;\
	for test in $(testall); do \
		./$< $$test tests/tests-$$test.txt $(tonull) && \
			printf "[\e[1;92mPASSED\e[0m]: " || { \
					printf "[\e[1;91mFAILED\e[0m]: ";result=1; \
				}; \
		echo $$test; \
	done; \
	if [ "$$result" -ne 0 ]; then \
		echo "TESTS FAILED!!!"; exit 1; \
	fi'
	@echo 'libcryptonight: OK!'



clean:
	rm $(objects) libcryptonight.a tests/*.bin || true

.PHONY: test
