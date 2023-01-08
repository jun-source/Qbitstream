#ifndef PARAMS_NTRU_H
#define PARAMS_NTRU_H

#define NTRU_HPS
#define NTRU_N 509
#define NTRU_LOGQ 11

/* Do not modify below this line */

#define NTRU_Q (1 << NTRU_LOGQ)
#define NTRU_WEIGHT (NTRU_Q/8 - 2)

#define NTRU_SEEDBYTES       32
#define NTRU_PRFKEYBYTES     32
#define NTRU_SHAREDKEYBYTES  32

#define NTRU_SAMPLE_IID_BYTES  (NTRU_N-1)
#define NTRU_SAMPLE_FT_BYTES   ((30*(NTRU_N-1)+7)/8)
#define NTRU_SAMPLE_FG_BYTES   (NTRU_SAMPLE_IID_BYTES+NTRU_SAMPLE_FT_BYTES)
#define NTRU_SAMPLE_RM_BYTES   (NTRU_SAMPLE_IID_BYTES+NTRU_SAMPLE_FT_BYTES)

#define NTRU_PACK_DEG (NTRU_N-1)
#define NTRU_PACK_TRINARY_BYTES    ((NTRU_PACK_DEG+4)/5)

#define NTRU_OWCPA_MSGBYTES       (2*NTRU_PACK_TRINARY_BYTES)
#define NTRU_OWCPA_PUBLICKEYBYTES ((NTRU_LOGQ*NTRU_PACK_DEG+7)/8)
#define NTRU_OWCPA_SECRETKEYBYTES (2*NTRU_PACK_TRINARY_BYTES + NTRU_OWCPA_PUBLICKEYBYTES)
#define NTRU_OWCPA_BYTES          ((NTRU_LOGQ*NTRU_PACK_DEG+7)/8)

#define NTRU_PUBLICKEYBYTES  (NTRU_OWCPA_PUBLICKEYBYTES)
#define NTRU_SECRETKEYBYTES  (NTRU_OWCPA_SECRETKEYBYTES + NTRU_PRFKEYBYTES)
#define NTRU_CIPHERTEXTBYTES (NTRU_OWCPA_BYTES)

#endif
