/*
randombytes_deterministic.h version 20140115
Malte Tancred
Public domain.
*/

#ifndef randombytes_deterministic_H
#define randombytes_deterministic_H

#ifdef __cplusplus
extern "C" {
#endif

extern void randombytes(unsigned char *,unsigned long long);

#ifdef __cplusplus
}
#endif

#ifndef randombytes_implementation
#define randombytes_implementation "deterministic"
#endif

#endif
