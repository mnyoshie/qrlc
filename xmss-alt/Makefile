CFLAGS = -Wall -g -O3 -Wextra -Wpedantic -D_FORTIFY_SOURCE=2 #-fsanitize=address
LDFLAGS = -lcrypto
#LDFLAGS += -fsanitize=address

csources = fips202.c
csources += hash.c 
csources += hash_address.c
csources += wots.c
csources += xmss_common.c
objects = $(subst .c,.o,$(csources))

ifeq ($(V),1)
  Q=
else
  Q=@
endif

all: libxmss_qrl.a libxmssf_qrl.a

libxmss_qrl.a : $(objects) algsxmss.o
	$(AR) rcs $@ $^

libxmssf_qrl.a : $(objects) algsxmss_fast.o
	$(AR) rcs $@ $^

%.o : %.c
	@echo "  CC $< $@"
	$(Q)$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm $(objects) algsxmss_fast.o algsxmss.o libxmss_qrl.a libxmssf_qrl.a || true

