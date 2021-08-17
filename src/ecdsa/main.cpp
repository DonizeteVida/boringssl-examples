#include "openssl/rsa.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/engine.h"

#include <string.h>

#include "util.h"

#include <iostream>

static char* teste;

void ECDSA_test_sign(EVP_PKEY* pkey) {
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
	assert(ctx, "Encrypt context is NULL");
	assert(EVP_PKEY_sign_init(ctx), "Encrypt sign cannot be started");

	unsigned char in[] = "Donizete Junior Ribeiro Vida";
	unsigned long in_len = sizeof(in);

	unsigned char* out = 0;
	unsigned long out_len = 0;

	assert(EVP_PKEY_sign(ctx, NULL, &out_len, in, in_len), "Signature size cannot be calculated");
	std::cout << "Digest length: " << out_len << std::endl;

	out = (unsigned char*) OPENSSL_malloc(out_len);

	assert(EVP_PKEY_sign(ctx, out, &out_len, in, in_len), "Signature cannot be transfered");

	//out[out_len] = '\0';

	assert(write_file((char*)"signature.data", (char*)out), "Signature cannot be write");

	OPENSSL_free(out);
}

void ECDSA_test_verify(EVP_PKEY* pkey) {
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
	assert(ctx, "Encrypt context is NULL");
	assert(EVP_PKEY_verify_init(ctx), "Verify sign cannot be started");

	unsigned char in[] = "Donizete Junior Ribeiro Vida";
	unsigned long in_len = sizeof(in);

	unsigned char* out = 0;
	unsigned long out_len = 0;

	assert(out = (unsigned char*) read_file((char*)"signature.data"), "Signed content was not found or something else");
	assert((out_len = strlen((char*)out)), "Signed content length cannot be counted");

	//We wont use assert here because it isn't a code error
	int result = EVP_PKEY_verify(ctx, in, in_len, out, out_len);
	if (result) {
		std::cout << "Data was verified successfully" << std::endl;
	} else {
		std::cerr << "Data wasn't verified" << std::endl;
	}
}

void ECDSA_generate_key() {
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	assert(ctx, "Context cannot be created");

	//All this is to generate EVP_PKEY key properly
	assert(EVP_PKEY_paramgen_init(ctx), "ParamGen cannot be started");
	assert(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp521r1), "Curve cannot be set");
	assert(EVP_PKEY_CTX_set_ec_param_enc(ctx, OPENSSL_EC_NAMED_CURVE), "Encoding cannot be set");

	//Creating a new key from filled context
	EVP_PKEY* param_gen_key = NULL;
	assert(EVP_PKEY_paramgen(ctx, &param_gen_key), "EVP_PKEY key cannot be created from context");

	//Creating a new context as we need to use their API's
	EVP_PKEY_CTX* keygen_ctx = EVP_PKEY_CTX_new(param_gen_key, NULL);
	assert(keygen_ctx, "ParamGen context cannot be created");
	assert(EVP_PKEY_keygen_init(keygen_ctx), "KeyGen cannot be started");
	EVP_PKEY* keygen_key = NULL;
	assert(EVP_PKEY_keygen(keygen_ctx, &keygen_key), "KeyGen key cannot be created");

	ECDSA_test_sign(keygen_key);
	ECDSA_test_verify(keygen_key);

	//We'll write this key
	BIO* bio_priv_file = BIO_new_file("priv.pem", "wr");
	BIO* bio_pub_file = BIO_new_file("pub.pem", "wr");

	assert(bio_priv_file, "File bio_priv_file was not created");
	assert(bio_pub_file, "File bio_pub_file was not created");

	EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(keygen_key);
	assert(ec_key, "EC_KEY was not generated");

	assert(PEM_write_bio_ECPrivateKey(bio_priv_file, ec_key, NULL, NULL, 0, NULL, NULL), "ECPrivateKey cannot be write");
	assert(PEM_write_bio_EC_PUBKEY(bio_pub_file, ec_key), "EC_PUBKEY cannot be write");
}

void ECDSA_test_start() {
	ECDSA_generate_key();

	return;

	BIO* bio_pub_file = BIO_new_file("pub.pem", "r");
	BIO* bio_priv_file = BIO_new_file("priv.pem", "r");

	assert(bio_priv_file, "We cannot read a PEM file");
	assert(bio_pub_file, "We cannot read a PEM file");

	EC_KEY* ec_priv_key = NULL;
	EC_KEY* ec_pub_key = NULL;
	assert(PEM_read_bio_ECPrivateKey(bio_priv_file, &ec_priv_key, NULL, NULL), "We cannot retrieve file as EC Public Key");
	assert(PEM_read_bio_EC_PUBKEY(bio_pub_file, &ec_pub_key, NULL, NULL), "We cannot retrieve file as EC Public Key");
}

void ECDSA_test() {
	printf("Inicio de um sonho\n");
	ECDSA_test_start();
	printf("Deu tudo certo!\n");
}

