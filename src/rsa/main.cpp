#include "openssl/rsa.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/engine.h"
#include "util.h"

void RSA_generate_key() {
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	assert(ctx, "Context cannot be created");

	//All this is to generate EVP_PKEY keys properly
	assert(EVP_PKEY_keygen_init(ctx), "KeyGen cannot be started");
	assert(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048), "Bits cannot be set");
	BIGNUM* expiration = BN_new();
	BN_set_word(expiration, 0x10001);
	assert(EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, expiration), "Expiration date cannot be set");

	//Creating a new key from filled context
	EVP_PKEY* key = NULL;
	assert(EVP_PKEY_keygen(ctx, &key), "EVP_PKEY key cannot be created from context");

	//Creating a new context as we need to use their API's
	EVP_PKEY_CTX* encrypt_context = EVP_PKEY_CTX_new(key, NULL);
	assert(encrypt_context, "Encrypt context cannot be created");
	assert(EVP_PKEY_encrypt_init(encrypt_context), "Encrypt cannot be started");
	assert(EVP_PKEY_CTX_set_rsa_padding(encrypt_context, RSA_PKCS1_OAEP_PADDING), "We cannot set PADDING");

	EVP_PKEY* rsa_pkey = EVP_PKEY_CTX_get0_pkey(encrypt_context);
	assert(rsa_pkey, "Encrypt key was not generated");
	RSA* rsa_key = EVP_PKEY_get0_RSA(rsa_pkey);
	assert(rsa_key, "RSA key was not generated");

	//We'll write this key
	BIO* bio_file = BIO_new_file("rsa_key.pem", "wr");
	assert(bio_file, "File was not created");
	//assert(PEM_write_bio_RSAPrivateKey(bio_file, rsa_key, NULL, NULL, 0, NULL, NULL), "RSA private key cannot be write");
	//assert(PEM_write_bio_RSAPublicKey(bio_file, rsa_key), "RSA public key cannot be write");
	assert(PEM_write_bio_RSA_PUBKEY(bio_file, rsa_key), "RSA public key cannot be write");
}

void RSA_test_encrypt() {
	RSA_generate_key();

	BIO* bio_file = BIO_new_file("rsa_key.pem", "wr");
	assert(bio_file, "We cannot read a PEM file");

	RSA* rsa = NULL;
	//assert(PEM_read_bio_RSAPrivateKey(bio_file, &rsa, NULL, NULL), "We cannot retrieve file as RSA Private Key");
	//assert(PEM_read_bio_RSAPublicKey(bio_file, &rsa, NULL, NULL), "We cannot retrieve file as RSA Public Key");
	assert(PEM_read_bio_RSA_PUBKEY(bio_file, &rsa, NULL, NULL), "We cannot retrieve file as RSA Public Key");
}

void RSA_test() {
	printf("Inicio de um sonho\n");
	RSA_test_encrypt();
	printf("Deu tudo certo!\n");
}
