/*
 * ECKeyRecover.cpp
 *
 *  Created on: Aug 22, 2021
 *      Author: doni
 */

#include "openssl/evp.h"
#include "openssl/bio.h"
#include "openssl/pem.h"
#include "openssl/ec.h"

#include "util.h"

#include "ECKeyRecover.h"

ECKeyRecover::ECKeyRecover(const char* pemName) : KeyRecover(pemName) {}

ECKeyRecover::~ECKeyRecover() {}

bool ECKeyRecover::initialize(EVP_PKEY* pkey, BIO* bio) {
	EC_KEY* ec_key = NULL;

	assert(PEM_read_bio_ECPrivateKey(bio, &ec_key, NULL, NULL), "We cannot retrieve file as EC Private Key");
	assert(PEM_read_bio_EC_PUBKEY(bio, &ec_key, NULL, NULL), "We cannot retrieve file as EC Public Key");

	assert(EVP_PKEY_set1_EC_KEY(pkey, ec_key), "EC_KEY cannot be set to EVP_PKEY");
	return true;
}

