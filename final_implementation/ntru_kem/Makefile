CC=/usr/bin/gcc
LDFLAGS=-lcrypto

SOURCES = ntru_key_gen.c crypto_sort.c fips202_ntru.c kem.c owcpa.c \
	pack3.c packq.c poly.c sample.c verify.c rng.c 
HEADERS = api.h crypto_sort.h fips202_ntru.h kem.h poly.h owcpa.h params_ntru.h \
	sample.h verify.h rng.h \

ntru_key_gen: $(HEADERS) $(SOURCES)
	$(CC) -o $@ $(SOURCES) $(LDFLAGS)

.PHONY: clean

clean:
	-rm ntru_key_gen

