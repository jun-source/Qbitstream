CC=/usr/bin/gcc
LDFLAGS=-lcrypto -Intru_kem/

SOURCES = main.c ntru_kem/crypto_sort.c ntru_kem/fips202.c ntru_kem/kem.c ntru_kem/owcpa.c ntru_kem/pack3.c ntru_kem/packq.c ntru_kem/poly.c ntru_kem/sample.c ntru_kem/verify.c ntru_kem/rng.c 
HEADERS = ntru_kem/api.h ntru_kem/crypto_sort.h ntru_kem/fips202.h ntru_kem/kem.h ntru_kem/poly.h ntru_kem/owcpa.h ntru_kem/params.h ntru_kem/sample.h ntru_kem/verify.h ntru_kem/rng.h

main: $(HEADERS) $(SOURCES)
	$(CC) -o $@ $(SOURCES) $(LDFLAGS)

.PHONY: clean

clean:
	-rm main

