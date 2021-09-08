/*
 * KeyRecover.cpp
 *
 *  Created on: Aug 22, 2021
 *      Author: doni
 */

#include "openssl/evp.h"
#include "openssl/bio.h"
#include "openssl/pem.h"

#include "util.h"

#include "KeyRecover.h"

KeyRecover::KeyRecover(const char* pemName) : pemName(pemName){}
KeyRecover::~KeyRecover(){}

bool KeyRecover::initialize(EVP_PKEY* pkey, BIO* bio) {
	return false;
}

EVP_PKEY* KeyRecover::operator()() {
	BIO *bio = BIO_new_file(pemName, "r");
	assert(bio);

	EVP_PKEY *pkey = EVP_PKEY_new();

	assert(initialize(pkey, bio));

	BIO_free(bio);

	return pkey;
}

