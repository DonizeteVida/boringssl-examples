#include "openssl/rsa.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/engine.h"
#include "util.h"

#include <iostream>
#include <string.h>

static void RSA_test_encrypt(EVP_PKEY* pkey, unsigned char* out, unsigned long* out_len, unsigned char* in, long in_len) {
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
	assert(ctx);

	assert(EVP_PKEY_encrypt_init(ctx));
	//assert(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING), "Encrypt padding cannot be performed");

	assert(EVP_PKEY_encrypt(ctx, NULL, out_len, in, in_len));
	std::cout << "Encrypt length: " << *out_len << std::endl;

	assert(EVP_PKEY_encrypt(ctx, out, out_len, in, in_len));

	std::cout << "Encrypt content: " << out << std::endl;

	EVP_PKEY_CTX_free(ctx);
}

static void RSA_test_decrypt(EVP_PKEY* pkey, unsigned char* out, unsigned long *out_len, unsigned char* in, long in_len) {
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
	assert(ctx);

	assert(EVP_PKEY_decrypt_init(ctx));
	//assert(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING), "Decrypt padding cannot be performed");

	assert(EVP_PKEY_decrypt(ctx, NULL, out_len, in, in_len));
	assert(EVP_PKEY_decrypt(ctx, out, out_len, in, in_len));

	EVP_PKEY_CTX_free(ctx);
}

static void RSA_write_key(RSA* rsa_key) {
	//We'll write this key
	BIO* bio = BIO_new_file("key.pem", "w");

	assert(rsa_key);
	BIO_set_flags(bio, BIO_FLAGS_WRITE);

	assert(PEM_write_bio_RSAPrivateKey(bio, rsa_key, NULL, NULL, 0, NULL, NULL));
	assert(PEM_write_bio_RSAPublicKey(bio, rsa_key));
	assert(PEM_write_bio_RSA_PUBKEY(bio, rsa_key));

	BIO_free(bio);
}

static EVP_PKEY* RSA_test_recover_key() {
	BIO* bio = BIO_new_file("key.pem", "r");

	assert(bio);

	RSA* rsa_key = NULL;

	assert(PEM_read_bio_RSAPrivateKey(bio, &rsa_key, NULL, NULL));
	assert(PEM_read_bio_RSAPublicKey(bio, &rsa_key, NULL, NULL));
	assert(PEM_read_bio_RSA_PUBKEY(bio, &rsa_key, NULL, NULL));

	BIO_free(bio);

	EVP_PKEY* pkey = EVP_PKEY_new();

	assert(EVP_PKEY_set1_RSA(pkey, rsa_key));

	return pkey;
}

static EVP_PKEY* RSA_generate_key() {
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	assert(ctx);

	//All this is to generate EVP_PKEY keys properly
	assert(EVP_PKEY_keygen_init(ctx));
	assert(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048));
	BIGNUM *expiration = BN_new();
	BN_set_word(expiration, 0x10001);
	assert(EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, expiration));

	//Creating a new key from filled context
	EVP_PKEY *pkey = NULL;
	assert(EVP_PKEY_keygen(ctx, &pkey));

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
