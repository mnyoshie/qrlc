CXXFLAGS += -O3 -fPIE
CFLAGS += -O3 -fPIE

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
csources += reciprocal.c
csources += virtual_memory.c

check-cpu-feature = $(shell cat /proc/cpuinfo | grep $(1) > /dev/null; echo $$?)

ifeq ($(V),1)
  Q=
else
  Q=@
endif

machine := $(shell uname -m)
machine := $(shell echo $(machine) | sed -e 's/x86-64/x86_64/' -e 's/amd64/x86_64/' \
					-e 's/arm64/aarch64/' -e 's/armv8-a/aarch64/' )

ifeq ($(machine),x86_64)
  cxxsources += jit_compiler_x86.cpp
  cxxsources += assembly_generator_x86.cpp
  asms = jit_compiler_x86_static.S
  CXXFLAGS += -march=native
  CFLAGS += -march=native
  CFLAGS += -maes

  # HAVE cpuid
  ifeq ($(call check-cpu-feature,cpuid),0)
  CXXFLAGS += -DHAVE_CPUID
  CFLAGS += -DHAVE_CPUID
  endif
  
  # HAVE SSE3 
  ifeq ($(call check-cpu-feature,ssse3),0)
  csources += argon2_ssse3.c
  CXXFLAGS += -mssse3
  CFLAGS += -mssse3
  endif
  
  # HAVE AVX2
  ifeq ($(call check-cpu-feature,avx2),0)
  csources += argon2_avx2.c
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

%.bin: tests/%.o librandomx.a
	$(CXX) $< -L. -lrandomx -o $@

test: tests.bin
	./$< && echo 'librandomx: OK!'

clean:
	rm $(objects) *.bin

.PHONY: test
