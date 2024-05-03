# Makefile - Makefile for most linux based systems
# to get rid of cmake builds.

# Written by the QRLC Authors. Inspired from the Linux 
# kernel Makefile

#randomx version 1.2.1

CFLAGS += -O3 -std=gnu11 -fPIE
CXXFLAGS += -O3 -std=gnu++11 -fPIE

cxxsources =  aes_hash.cpp
cxxsources += allocator.cpp
cxxsources += blake2_generator.cpp
cxxsources += bytecode_machine.cpp
cxxsources += cpu.cpp
cxxsources += dataset.cpp
cxxsources += instruction.cpp
cxxsources += instructions_portable.cpp
cxxsources += randomx.cpp
cxxsources += soft_aes.cpp
cxxsources += superscalar.cpp
cxxsources += virtual_machine.cpp
cxxsources += vm_compiled.cpp
cxxsources += vm_compiled_light.cpp
cxxsources += vm_interpreted.cpp
cxxsources += vm_interpreted_light.cpp

csources += blake2/blake2b.c
csources += argon2_core.c
csources += argon2_ref.c
csources += argon2_avx2.c
csources += argon2_ssse3.c
csources += reciprocal.c
csources += virtual_memory.c

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
  cxxsources += jit_compiler_x86.cpp
  cxxsources += assembly_generator_x86.cpp
  asms = jit_compiler_x86_static.S
  CXXFLAGS += -march=native
  CFLAGS += -march=native
  CFLAGS += -maes

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
  cxxsources += jit_compiler_a64.cpp
  asms = jit_compiler_a64_static.S
  CXXFLAGS += -march=armv8-a+crypto
  CFLAGS += -march=armv8-a+crypto
endif

ifeq ($(machine),riscv64)
  cxxsources += jit_compiler_rv64.cpp
  asms = jit_compiler_rv64_static.S
endif


#####################################
#####################################

objects = $(patsubst %.cpp,%.o,$(cxxsources)) $(patsubst %.c,%.o,$(csources)) $(patsubst %.S,%.o,$(asms))

target : librandomx.a

librandomx.a : $(objects)
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

%.bin: %.o librandomx.a
	$(CXX) $< -L. -lrandomx -o $@

test: tests/tests.bin
	@./$< && echo 'librandomx: OK!'

clean:
	rm $(objects) librandomx.a tests/*.bin || true

.PHONY: test
