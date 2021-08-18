#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/engine.h"

#include "util.h"

#include <string.h>
#include <iostream>

static void ECDSA_test_sign(EVP_PKEY* pkey, unsigned char* sig, unsigned long* sig_len, unsigned char* dig, long dig_len) {
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
	assert(ctx, "Encrypt context is NULL");

	assert(EVP_PKEY_sign_init(ctx), "Encrypt sign cannot be started");
	assert(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()), "Sha digest cannot be set");

	assert(EVP_PKEY_sign(ctx, NULL, sig_len, dig, dig_len), "Signature size cannot be calculated");
	std::cout << "Digest length: " << *sig_len << std::endl;

	assert(EVP_PKEY_sign(ctx, sig, sig_len, dig, dig_len), "Signature cannot be transfered");

	std::cout << "Digest content: " << sig << std::endl;

	EVP_PKEY_CTX_free(ctx);
}

void ECDSA_test_verify(EVP_PKEY* pkey, unsigned char* sig, unsigned long sig_len, unsigned char* dig, long dig_len) {
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
	assert(ctx, "Encrypt context is NULL");
	assert(EVP_PKEY_verify_init(ctx), "Verify sign cannot be started");

	int result = EVP_PKEY_verify(ctx, sig, sig_len, dig, dig_len);
	if (result) {
		std::cout << "Data is okay" << std::endl;
	} else {
		std::cerr << "Data isn't okay" << std::endl;
	}
	EVP_PKEY_CTX_free(ctx);
}

void ECDSA_write_key(EC_KEY* ec_key) {
	//We'll write this key
	BIO* bio = BIO_new_file("key.pem", "w");

	assert(ec_key, "EC_KEY was not generated");
	BIO_set_flags(bio, BIO_FLAGS_WRITE);

	assert(PEM_write_bio_ECPrivateKey(bio, ec_key, NULL, NULL, 0, NULL, NULL), "ECPrivateKey cannot be write");
	assert(PEM_write_bio_EC_PUBKEY(bio, ec_key), "EC_PUBKEY cannot be write");

	BIO_free(bio);
}

EVP_PKEY* ECDSA_test_recover_key() {
	BIO* bio = BIO_new_file("key.pem", "r");

	assert(bio, "We cannot read a PEM file");

	EC_KEY* ec_key = NULL;

	assert(PEM_read_bio_ECPrivateKey(bio, &ec_key, NULL, NULL), "We cannot retrieve file as EC Public Key");
	assert(PEM_read_bio_EC_PUBKEY(bio, &ec_key, NULL, NULL), "We cannot retrieve file as EC Public Key");

	BIO_free(bio);

	EVP_PKEY* pkey = EVP_PKEY_new();
	assert(EVP_PKEY_set1_EC_KEY(pkey, ec_key), "EC_KEY cannot be set to EVP_PKEY");

	return pkey;
}

EVP_PKEY* ECDSA_generate_key() {
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	assert(ctx, "Context cannot be created");

	//All this is to generate EVP_PKEY key properly
	assert(EVP_PKEY_paramgen_init(ctx), "ParamGen cannot be started");
	assert(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp521r1), "Curve cannot be set");
	assert(EVP_PKEY_CTX_set_ec_param_enc(ctx, OPENSSL_EC_NAMED_CURVE), "Encoding cannot be set");

	//Creating a new key from filled context
	EVP_PKEY* paramgen_key = NULL;
	assert(EVP_PKEY_paramgen(ctx, &paramgen_key), "EVP_PKEY key cannot be created from context");

	//Creating a new context as we need to use their API's
	EVP_PKEY_CTX* keygen_ctx = EVP_PKEY_CTX_new(paramgen_key, NULL);
	assert(keygen_ctx, "ParamGen context cannot be created");
	assert(EVP_PKEY_keygen_init(keygen_ctx), "KeyGen cannot be started");
	EVP_PKEY* keygen_key = NULL;
	assert(EVP_PKEY_keygen(keygen_ctx, &keygen_key), "KeyGen key cannot be created");

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(paramgen_key);
	EVP_PKEY_CTX_free(keygen_ctx);

	return keygen_key;
}

void ECDSA_test_start() {

	unsigned char in[] = "Donizete Junior Ribeiro Vida";
	unsigned long in_len = sizeof(in);

	unsigned char buffer[2048];
	unsigned long buffer_len = 0;

	EVP_PKEY* pkey = ECDSA_generate_key();

	ECDSA_test_sign(pkey, buffer, &buffer_len, in, in_len);
	//in[in_len - 1] = 'A';
	ECDSA_test_verify(pkey, buffer, buffer_len, in, in_len);

	ECDSA_write_key(EVP_PKEY_get0_EC_KEY(pkey));
	EVP_PKEY* read_pkey = ECDSA_test_recover_key();
	//in[in_len - 1] = 'A';
	ECDSA_test_verify(read_pkey, buffer, buffer_len, in, in_len);


	EVP_PKEY_free(pkey);
}

void ECDSA_test() {
	printf("Inicio de um sonho\n");
	ECDSA_test_start();
	printf("Deu tudo certo!\n");
}

