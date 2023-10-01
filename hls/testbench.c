#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "poly_rq_mul.h"

#define NTRU_N 509
#define NTRU_Q 2048

#define NUM_TESTS 1000

int main(int argc, char *argv[]) {
	uint16_t a[QBIT_N], b[QBIT_N], r[QBIT_N], _r[QBIT_N];
	int i, j;
	FILE *fp;

	// Ensure degrees are at most NTRU_N - 1
	memset(a, 0, QBIT_N * sizeof(uint16_t));
	memset(b, 0, QBIT_N * sizeof(uint16_t));
	memset(r, 0, QBIT_N * sizeof(uint16_t));

	// Test vectors file
	if ((fp = fopen("poly_rq_mul_test_vectors.dat", "r")) == NULL) {
		printf("ERROR (Cannot read test vectors file)\n");
		return 1;
	}

	// Testbench loop
	for (i = 0; i < NUM_TESTS; i++) {
		// Read a * b = r from test vectors file
		for (j = 0; j < NTRU_N; j++) {
			fscanf(fp, "%hu", a + j);
		}

		for (j = 0; j < NTRU_N; j++) {
			fscanf(fp, "%hu", b + j);
		}

		for (j = 0; j < NTRU_N; j++) {
			fscanf(fp, "%hu", r + j);

			// Reduce modulo NTRU_Q to take into account hardware overflows
			r[j] = r[j] % NTRU_Q;
		}

		// Use hardware accelerator
		poly_rq_mul(_r, a, b);

		// Check results
		for (j = 0; j < QBIT_N; j++) {
			if (r[j] != _r[j]) {
				printf("ERROR (Test %d/%d, coeff %d): %d != %d\n", i + 1, NUM_TESTS, j, r[j], _r[j]);
				return 2;
			}
		}
	}

	fclose(fp);

	printf("Testbench PASSED\n");

	return 0;
}












