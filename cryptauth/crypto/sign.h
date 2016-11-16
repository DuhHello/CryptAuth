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

#ifndef CRYPTAUTH_SIGN_H
#define CRYPTAUTH_SIGN_H

#include "error.h"

typedef struct {
	unsigned char public_key[crypto_box_PUBLICKEYBYTES];
	unsigned char private_key[crypto_box_SECRETKEYBYTES];
} sign_keypair_t;

cryptauth_error_t *init_sign_keypair(sign_keypair_t *keypair);
cryptauth_error_t *read_sign_keypair(sign_keypair_t *keypair, FILE restrict *stream);
cryptauth_error_t free_keypair(sign_keypair_t *keypair);
cryptauth_error_t *write_sign_keypair(const sign_keypair_t *keypair, FILE restrict *stream);
cryptauth_error_t *sign_message(const sign_keypair_t *keypair, unsigned char *signature, 
	unsigned char *message, const unsigned long long message_len);
cryptauth_error_t *sign_message_prepend(const sign_keypair_t *keypair, unsigned char *new_message,
	unsigned char *message, unsigned long long message_len);
int verify_signature(const sign_keypair_t *keypair, const unsigned char *signature,
	const unsigned char *message, unsigned long long message_len);
int verify_prepend_signature(const sign_keypair_t *keypair, const unsigned char *signature,
	unsigned char *message, unsigned long long message_len);
#endif