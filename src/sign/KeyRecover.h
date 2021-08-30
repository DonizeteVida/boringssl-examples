/*
 * KeyRecover.h
 *
 *  Created on: Aug 22, 2021
 *      Author: doni
 */

#include "openssl/evp.h"
#include "openssl/bio.h"

#ifndef SIGN_KEYRECOVER_H_
#define SIGN_KEYRECOVER_H_

class KeyRecover {
public:
	KeyRecover(const char*);
	virtual ~KeyRecover();
	virtual bool initialize(EVP_PKEY*, BIO*);
	EVP_PKEY* operator()();
private:
	const char* pemName;
};

#endif /* SIGN_KEYRECOVER_H_ */
