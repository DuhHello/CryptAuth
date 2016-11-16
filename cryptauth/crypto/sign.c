/*
Copyright (c) 2016 The CryptAuth Project. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted 
provided that the following conditions are met:

	1. Redistributions of source code must retain the above copyright notice, this list of 
	conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright notice, this list of 
    conditions and the following disclaimer in the documentation and/or other materials provided 
    with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED 
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE 
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT 
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR 
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

See PATENTLICENSE.txt for the terms of the patent license, which applies to this software.
*/

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>

#include "error.h"
#include "sign.h"

// move this somewhere
cryptauth_error_t init_sodium() {
	if (sodium_init() == -1) {
		return CRYPTAUTH_SODIUMINITFAIL;
	}

	return CRYPTAUTH_OK;
}

cryptauth_error_t *init_sign_keypair(sign_keypair_t *keypair) {
	keypair = sodium_malloc(sizeof(sign_keypair_t));
	if (keypair == NULL) {
		return CRYPTAUTH_ALLOCFAIL;
	}

	crypto_sign_keypair(keypair->public_key, keypair->private_key);

	return CRYPTAUTH_OK;
}

cryptauth_error_t *init_sign_keypair_from_keys(sign_keypair_t *keypair, unsigned char *public_key,
	unsigned char *private_key) {

	keypair = sodium_malloc(sizeof(sign_keypair_t));
	if (keypair == NULL) {
		return CRYPTAUTH_ALLOCFAIL;
	}

	keypair->public_key = 

}

cryptauth_error_t free_keypair(sign_keypair_t *keypair) {
	sodium_free(keypair);

	return CRYPTAUTH_OK;
}


cryptauth_error_t *read_sign_keypair(sign_keypair_t *keypair, FILE restrict *stream) {
	if (fread(keypair, sizeof(keypair_t), 1, stream) != 1) {
		return CRYPTAUTH_READFAIL;
	}

	return CRYPTAUTH_OK;
}

cryptauth_error_t *write_sign_keypair(sign_keypair_t *keypair, FILE restrict *stream) {
	if (fwrite(keypair, sizeof(keypair_t), 1, stream) != 1) {
		return CRYPTAUTH_WRITEFAIL;
	}

	return CRYPTAUTH_OK;
}

cryptauth_error_t *sign_message(const sign_keypair_t *keypair, unsigned char *signature, 
	unsigned char *message, const unsigned long long message_len) {

	signature = sodium_malloc(sizeof(unsigned char) * crypto_sign_BYTES);
	if (signature == NULL) {
		return CRYPTAUTH_ALLOCFAIL;
	}

	crypto_sign_detached(signature, NULL, message, message_len, keypair->private_key);
	return CRYPTAUTH_OK;
}

cryptauth_error_t *sign_message_prepend(const sign_keypair_t *keypair, unsigned char *new_message,
	const unsigned char *message, const unsigned long long message_len) {

	unsigned int signed_message_len = message_len + crypto_sign_BYTES;
	new_message = sodium_malloc(sizeof(unsigned char) * signed_message_len);

	if (new_message == NULL) {
		return CRYPTAUTH_ALLOCFAIL;
	}

	crypto_sign(new_message, NULL, message, message_len, keypair->private_key);
	return CRYPTAUTH_OK;
}

int verify_signature(const sign_keypair_t *keypair, const unsigned char *signature,
	const unsigned char *message, unsigned long long message_len) {

	return crypto_sign_verify_detached(signature, message, message_len, keypair->public_key);
}

int verify_prepend_signature(const sign_keypair_t *keypair, const unsigned char *signature,
	unsigned char *message, unsigned long long message_len) {

	return crypto_sign_open(signature, NULL, message, message_len, keypair->public_key);
}


