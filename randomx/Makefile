CXXFLAGS += -O3
CFLAGS += -O3

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

csources += argon2_avx2.c
csources += blake2/blake2b.c
csources += argon2_core.c
csources += argon2_ref.c
csources += argon2_ssse3.c
csources += reciprocal.c
csources += virtual_memory.c

ifeq ($(V),1)
  Q=
else
  Q=@
endif

machine = $(shell uname -m)
ifeq ($(machine),x86_64)
cxxsources += jit_compiler_x86.cpp
cxxsources += assembly_generator_x86.cpp
asms = jit_compiler_x86_static.S
endif

ifeq ($(machine),aarch64)
cxxsources += jit_compiler_a64.cpp
asms = jit_compiler_a64_static.S
endif

ifeq ($(machine),riscv64)
cxxsources += jit_compiler_rv64.cpp
sources += jit_compiler_rv64_static.S
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

test: librandomx.a
	make -C tests CXXFLAGS="-L.. -lrandomx -I.." target=tests run && echo 'librandomx: OK!'

clean:
	rm $(objects)

.PHONY: test
