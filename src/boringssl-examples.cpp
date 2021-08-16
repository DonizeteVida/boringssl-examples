//============================================================================
// Name        : boringssl-examples.cpp
// Author      : Donizete Vida
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include "openssl/evp.h"

#include "rsa/rsa_example.h"
#include "ecdh/ecdh_example.h"

int main() {
	OpenSSL_add_all_algorithms();
	OPENSSL_add_all_algorithms_conf();
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();

	//RSA_test();
	ECDH_test();

	return 0;
}
