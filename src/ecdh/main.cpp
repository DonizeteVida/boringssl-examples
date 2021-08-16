#include "openssl/rsa.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/engine.h"
#include "util.h"

void ECDH_generate_key() {
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
	EVP_PKEY_CTX* param_gen_ctx = EVP_PKEY_CTX_new(param_gen_key, NULL);
	assert(param_gen_ctx, "ParamGen context cannot be created");
	assert(EVP_PKEY_keygen_init(param_gen_ctx), "KeyGen cannot be started");
	EVP_PKEY* keygen_key = NULL;
	assert(EVP_PKEY_keygen(param_gen_ctx, &keygen_key), "KeyGen key cannot be created");

	EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(keygen_key);
	assert(ec_key, "EC_KEY was not generated");

	//We'll write this key
	BIO* bio_file = BIO_new_file("ecdh_key.pem", "wr");
	assert(bio_file, "File was not created");
	assert(PEM_write_bio_ECPrivateKey(bio_file, ec_key, NULL, NULL, 0, NULL, NULL), "ECPrivateKey cannot be write");
	assert(PEM_write_bio_EC_PUBKEY(bio_file, ec_key), "EC_PUBKEY cannot be write");
}

void ECDH_test_encrypt() {
	ECDH_generate_key();

	BIO* bio_file = BIO_new_file("ecdh_key.pem", "wr");
	assert(bio_file, "We cannot read a PEM file");

	RSA* rsa = NULL;
	//assert(PEM_read_bio_RSAPrivateKey(bio_file, &rsa, NULL, NULL), "We cannot retrieve file as RSA Private Key");
	//assert(PEM_read_bio_RSAPublicKey(bio_file, &rsa, NULL, NULL), "We cannot retrieve file as RSA Public Key");
	assert(PEM_read_bio_RSA_PUBKEY(bio_file, &rsa, NULL, NULL), "We cannot retrieve file as RSA Public Key");
}

void ECDH_test() {
	printf("Inicio de um sonho\n");
	ECDH_test_encrypt();
	printf("Deu tudo certo!\n");
}
