CC = gcc
CFLAGS = -Wall -g -O3 -Wextra -Wpedantic -D_FORTIFY_SOURCE=2 #-fsanitize=address
LDLIBS = -lcrypto
#LDLIBS += -fsanitize=address

SOURCES = algsxmss.c
SOURCES += algsxmss_fast.c
SOURCES += fips202.c
SOURCES += hash.c 
SOURCES += hash_address.c
SOURCES += wots.c
SOURCES += xmss_common.c
OBJECTS = $(subst .c,.o,$(SOURCES))

SOURCES_FAST = $(subst boilerplate,algsxmss_fast.c,$(SOURCES))
OBJECTS_FAST = $(subst .c,.o,$(SOURCES_FAST))
HEADERS_FAST = $(subst xmss_core.c,xmss_core_fast.c,$(HEADERS))

all: libxmss_qrl.a

libxmss_qrl.a : $(OBJECTS)
	$(AR) rcs $@ $^

$(OBJECTS) : %.o:%.c


clean:
	rm $(OBJECTS)
