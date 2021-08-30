/*
 * ECKeyRecover.h
 *
 *  Created on: Aug 22, 2021
 *      Author: doni
 */

#ifndef SIGN_ECKEYRECOVER_H_
#define SIGN_ECKEYRECOVER_H_

#include "KeyRecover.h"

class ECKeyRecover: public virtual KeyRecover {
public:
	ECKeyRecover(const char*);
	virtual ~ECKeyRecover();
	bool initialize(EVP_PKEY*, BIO*);
};

#endif /* SIGN_ECKEYRECOVER_H_ */
