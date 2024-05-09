# Makefile - Makefile for most linux based systems
# to get rid of cmake builds.

# Written by the QRLC Authors. Inspired from the Linux 
# kernel Makefile

#randomx version 1.2.1

CFLAGS += -O3 -std=gnu11 -fPIE
CXXFLAGS += -O3 -std=gnu++11 -fPIE

-include ../config.mk

CFLAGS += $(EXTRACFLAGS)
CXXFLAGS += $(EXTRACXXFLAGS)

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

ifeq ($(V),1)
  Q=
else
  tonull=>/dev/null 2>/dev/null
  Q=@
endif

ifeq ($(feature-atomic),1)
  CXXFLAGS += -DHAVE_CXX_ATOMICS
endif

ifeq ($(feature-hwcap),1)
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
  ifeq ($(feature-ssse3),1)
  CXXFLAGS += -mssse3
  CFLAGS += -mssse3
  endif
  
  # HAVE AVX2
  ifeq ($(feature-avx2),1)
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
