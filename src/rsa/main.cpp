#include "openssl/rsa.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/engine.h"
#include "util.h"

#include <iostream>
#include <string.h>

static void RSA_test_encrypt(EVP_PKEY* pkey, unsigned char* out, unsigned long* out_len, unsigned char* in, long in_len) {
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
	assert(ctx, "Encrypt context is NULL");

	assert(EVP_PKEY_encrypt_init(ctx), "Encrypt sign cannot be performed");
	//assert(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING), "Encrypt padding cannot be performed");

	assert(EVP_PKEY_encrypt(ctx, NULL, out_len, in, in_len), "Encrypt length cannot be performed");
	std::cout << "Encrypt length: " << *out_len << std::endl;

	assert(EVP_PKEY_encrypt(ctx, out, out_len, in, in_len), "Encrypt cannot be performed");

	std::cout << "Encrypt content: " << out << std::endl;

	EVP_PKEY_CTX_free(ctx);
}

static void RSA_test_decrypt(EVP_PKEY* pkey, unsigned char* out, unsigned long *out_len, unsigned char* in, long in_len) {
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
	assert(ctx, "Encrypt context is NULL");

	assert(EVP_PKEY_decrypt_init(ctx), "Encrypt init cannot be performed");
	//assert(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING), "Decrypt padding cannot be performed");

	assert(EVP_PKEY_decrypt(ctx, NULL, out_len, in, in_len), "Decrypt length cannot be performed");
	assert(EVP_PKEY_decrypt(ctx, out, out_len, in, in_len), "Decrypt cannot be performed");

	EVP_PKEY_CTX_free(ctx);
}

static void RSA_write_key(RSA* rsa_key) {
	//We'll write this key
	BIO* bio = BIO_new_file("key.pem", "w");

	assert(rsa_key, "EC_KEY was not generated");
	BIO_set_flags(bio, BIO_FLAGS_WRITE);

	assert(PEM_write_bio_RSAPrivateKey(bio, rsa_key, NULL, NULL, 0, NULL, NULL), "RSAPrivateKey cannot be performed");
	assert(PEM_write_bio_RSAPublicKey(bio, rsa_key), "RSAPrivateKey cannot be performed");
	assert(PEM_write_bio_RSA_PUBKEY(bio, rsa_key), "RSA_PUBKEY cannot be write");

	BIO_free(bio);
}

static EVP_PKEY* RSA_test_recover_key() {
	BIO* bio = BIO_new_file("key.pem", "r");

	assert(bio, "We cannot read a PEM file");

	RSA* rsa_key = NULL;

	assert(PEM_read_bio_RSAPrivateKey(bio, &rsa_key, NULL, NULL), "We cannot retrieve file as RSAPrivateKey");
	assert(PEM_read_bio_RSAPublicKey(bio, &rsa_key, NULL, NULL), "We cannot retrieve file as RSAPublicKey");
	assert(PEM_read_bio_RSA_PUBKEY(bio, &rsa_key, NULL, NULL), "We cannot retrieve file as RSAPublicKey");

	BIO_free(bio);

	EVP_PKEY* pkey = EVP_PKEY_new();

	assert(EVP_PKEY_set1_RSA(pkey, rsa_key), "EVP_PKEY_set1_RSA cannot be performed");

	return pkey;
}

static EVP_PKEY* RSA_generate_key() {
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	assert(ctx, "Context cannot be created");

	//All this is to generate EVP_PKEY keys properly
	assert(EVP_PKEY_keygen_init(ctx), "KeyGen cannot be started");
	assert(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048), "Bits cannot be set");
	BIGNUM *expiration = BN_new();
	BN_set_word(expiration, 0x10001);
	assert(EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, expiration), "Expiration date cannot be set");

	//Creating a new key from filled context
	EVP_PKEY *pkey = NULL;
	assert(EVP_PKEY_keygen(ctx, &pkey),"EVP_PKEY key cannot be created from context");

	EVP_PKEY_CTX_free(ctx);

	return pkey;
}

static void RSA_test_start() {

	unsigned char in[] = "DONI";
	unsigned long in_len = sizeof(in);

	unsigned char out[2048];
	unsigned long out_len = 0;

	EVP_PKEY* pkey = RSA_generate_key();

	RSA_test_encrypt(pkey, out, &out_len, in, in_len);
	//in[in_len - 1] = 'A';
	RSA_test_decrypt(pkey, out, &out_len, in, in_len);

	RSA_write_key(EVP_PKEY_get0_RSA(pkey));
	EVP_PKEY* read_pkey = RSA_test_recover_key();
	//in[in_len - 1] = 'A';
	RSA_test_decrypt(read_pkey, out, &out_len, in, in_len);


	EVP_PKEY_free(pkey);
	EVP_PKEY_free(read_pkey);
}

void RSA_test() {
	printf("Inicio de um sonho\n");
	RSA_test_start();
	printf("Deu tudo certo!\n");
}
