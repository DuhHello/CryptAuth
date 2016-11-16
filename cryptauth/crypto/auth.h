#ifndef AUTH_H
#define AUTH_H

#include <time.h>
#include <stdint.h>

#include "sign.h"

typedef struct {
	unsigned char public_key[crypto_box_PUBLICKEYBYTES];
	time_t time;
	uint64_t nonce;
} authenticate_t;

#endif