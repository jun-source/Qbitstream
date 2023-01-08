CC=/usr/bin/gcc
LDFLAGS=-lcrypto 

SOURCES = dilith_key_gen.c aes256ctr.c fips202.c ntt.c packing.c poly.c polyvec.c \
	reduce.c rng.c rounding.c sign.c symmetric-aes.c symmetric-shake.c
HEADERS = api_dil.h config.h fips202.h ntt.h packing.h params.h poly.h polyvec.h \
	reduce.h rng.h rounding.h sign.h symmetric.h

dilith_key_gen: $(HEADERS) $(SOURCES)
	$(CC) -o $@ $(SOURCES) $(LDFLAGS)

.PHONY: clean

clean:
	-rm dilith_key_gen

