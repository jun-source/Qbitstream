#ifndef __POLY_RQ_MUL_H__
#define __POLY_RQ_MUL_H__

#include <stdint.h>

#define QBIT_N 512

void poly_rq_mul(uint16_t r[QBIT_N], uint16_t a[QBIT_N], uint16_t b[QBIT_N]);

#endif
