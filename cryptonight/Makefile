# Makefile - Makefile for most linux based systems
# to get rid of cmake builds.

# Written by the QRLC Authors. Inspired from the Linux 
# kernel Makefile

#cryptonight v2: https://github.com/monero-project/monero/commit/5fd83c13fbf8dc304909345e60a853c15b0de1e5#diff-7000dc02c792439471da62856f839d62


CFLAGS += -O0 -fPIE -I./include
CXXFLAGS += -O0 -fPIE -I./include 

csources += $(directory)aesb.c
csources += $(directory)blake256.c
csources += $(directory)chacha.c
#csources += $(directory)crypto-ops-data.c
#csources += $(directory)crypto-ops.c
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

feature-check = $(shell $(CXX) $(CXXFLAGS) tests/$(1).cpp -o $(1)_test.bin $(tonull) && echo 1 || echo 0)
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
  cxxsources += $(directory)CryptoNight_x86_vaes.cpp
  CXXFLAGS += -march=native
  CFLAGS += -march=native
  CFLAGS += -maes

  # HAVE cpuid
  ifeq ($(call check-cpu-feature,cpuid),1)
  CXXFLAGS += -DHAVE_CPUID
  CFLAGS += -DHAVE_CPUID
  endif
  
  # HAVE SSSE3 
  ifeq ($(call check-compiler-feature,__SSSE3__,-mssse3),1)
  csources += argon2_ssse3.c
  CXXFLAGS += -mssse3
  CFLAGS += -mssse3
  endif
  
  # HAVE AVX2
  ifeq ($(call check-compiler-feature,__AVX2__,-mavx2),1)
  csources += argon2_avx2.c
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
  cxxsources += jit_compiler_rv64.cpp
  asms = jit_compiler_rv64_static.S
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

%.bin: tests/%.o libcryptonight.a
	$(CXX) $< -L. -lcryptonight -o $@

test: main.bin
	@bash -c ' \
	result=0;\
	for test in $(testall); do \
		./main.bin $$test tests/tests-$$test.txt $(tonull) && \
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
	rm $(objects) libcryptonight.a *.bin || true

.PHONY: test
