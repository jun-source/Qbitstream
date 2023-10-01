#include "poly_rq_mul.h"

#include "ap_cint.h"

void poly_rq_mul(uint16_t r[QBIT_N], uint16_t a[QBIT_N], uint16_t b[QBIT_N]) {
    uint11 buffer[QBIT_N];
    uint10 i, k;
    uint10 a_index;

    fixed_b_loop: for (i = 0; i < QBIT_N; i++) {
        output_coeff_loop: for (k = 0; k < QBIT_N; k++) {
        	// a_index = k == 0 ? QBIT_N - i : a_index + 1;
            // a_index = (a_index == QBIT_N) ? 0 : a_index;


        	a_index = QBIT_N - i + k;
			a_index = a_index >= QBIT_N ? a_index - QBIT_N : a_index;

            buffer[k] = i == 0 ? 0 : buffer[k];
            buffer[k] += (uint11) b[i] * (uint11) a[a_index];
        }
    }

    copy_loop: for (i = 0; i < QBIT_N; i++) {
        r[i] = buffer[i];
    }
}
