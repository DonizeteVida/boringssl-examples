#include "openssl/rsa.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/engine.h"
#include "util.h"

#include <iostream>
#include <string.h>

void RSA_encrypt(EVP_PKEY *pkey) {
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);

	assert(EVP_PKEY_encrypt_init(ctx), "Encrypt context cannot be started");
	assert(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING), "We cannot set PADDING");

	unsigned char in[] = "Donizete Junior Ribeiro Vida";
	unsigned long in_len = sizeof(in);

	unsigned char* out = 0;
	unsigned long out_len = 0;

	assert(EVP_PKEY_encrypt(ctx, NULL, &out_len, in, in_len), "Encrypt size cannot be calculated");
	std::cout << "Encrypt size: " << out_len << std::endl;

	assert(out = (unsigned char*) OPENSSL_malloc(out_len + 1), "OPENSSL_malloc cannot be performed");
	assert(EVP_PKEY_encrypt(ctx, out, &out_len, in, in_len), "Encrypt buffer transfer cannot be performed");
	out[out_len] = '\0';

	assert(write_file((char*)"encrypt.txt", (char*) out), "Encrypt.data cannot be write");
	std::cout << "Encrypt data: " << out << std::endl;
	OPENSSL_free(out);
}

void RSA_decrypt(EVP_PKEY* pkey) {
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);

	assert(EVP_PKEY_decrypt_init(ctx), "Decrypt context cannot be started");
	assert(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING), "We cannot set PADDING");

	char* in = read_file((char*)"encrypt.txt");
	unsigned int in_len = strlen(in);

	unsigned char* out = 0;
	unsigned long out_len = 0;

	std::cout << "Encrypt data: " << in << std::endl;

	assert(EVP_PKEY_decrypt(ctx, NULL, &out_len, (uint8_t*) in, in_len), "Decrypt size cannot be calculated");
	std::cout << "Decrypt size: " << out_len << std::endl;

	out = (unsigned char*) OPENSSL_malloc(out_len);
	assert(EVP_PKEY_decrypt(ctx, out, &out_len, (uint8_t*) in, in_len), "Decrypt buffer transfer cannot be performed");

	std::cout << "Decrypt data: " << out << std::endl;
}

void RSA_generate_key() {
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

	RSA_encrypt(pkey);
	RSA_decrypt(pkey);

	RSA *rsa_key = NULL;
	assert(rsa_key = EVP_PKEY_get0_RSA(pkey), "RSA key was not generated");

	//We'll write this key
	BIO *bio_priv_file = BIO_new_file("priv.pem", "w");
	BIO *bio_pub_file = BIO_new_file("pub.pem", "w");

	assert(bio_priv_file, "File bio_priv_file was not created");
	assert(bio_pub_file, "File bio_pub_file was not created");

	assert(PEM_write_bio_RSAPrivateKey(bio_priv_file, rsa_key, NULL, NULL, 0, NULL, NULL), "RSA private key cannot be write");
	assert(PEM_write_bio_RSA_PUBKEY(bio_pub_file, rsa_key), "RSA public key cannot be write");
}

void RSA_reload_key() {
	BIO *bio_priv_file = BIO_new_file("priv.pem", "r");
	assert(bio_priv_file, "We cannot read a PEM file");

	RSA *rsa_priv = NULL;
	//assert(PEM_read_bio_RSAPrivateKey(bio_file, &rsa, NULL, NULL), "We cannot retrieve file as RSA Private Key");
	//assert(PEM_read_bio_RSAPublicKey(bio_file, &rsa, NULL, NULL), "We cannot retrieve file as RSA Public Key");
	assert(PEM_read_bio_RSAPrivateKey(bio_priv_file, &rsa_priv, NULL, NULL), "We cannot retrieve file as RSA Public Key");
}

void RSA_test_start() {
	RSA_generate_key();
}

void RSA_test() {
	printf("Inicio de um sonho\n");
	RSA_test_start();
	printf("Deu tudo certo!\n");
}
