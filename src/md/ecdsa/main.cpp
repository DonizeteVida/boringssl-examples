/*
 * main.cpp
 *
 *  Created on: Sep 7, 2021
 *      Author: doni
 */

#include "openssl/evp.h"
#include "openssl/ec.h"
#include "openssl/digest.h"
#include "openssl/nid.h"
#include "openssl/bio.h"
#include "openssl/pem.h"

#include "util.h"

static EVP_PKEY* EC_read_key() {
	BIO *bio = BIO_new_file("key.pem", "r");

	assert(bio, "We cannot read a PEM file");

	EC_KEY *ec_key = NULL;

	assert(PEM_read_bio_ECPrivateKey(bio, &ec_key, NULL, NULL), "We cannot retrieve file as EC Private Key");
	assert(PEM_read_bio_EC_PUBKEY(bio, &ec_key, NULL, NULL), "We cannot retrieve file as EC Public Key");

	BIO_free(bio);

	EVP_PKEY *pkey = EVP_PKEY_new();
	assert(EVP_PKEY_set1_EC_KEY(pkey, ec_key), "EC_KEY cannot be set to EVP_PKEY");

	return pkey;
}

static void EC_write_key(EC_KEY *key) {
	BIO *bio = BIO_new_file("key.pem", "w");

	assert(key, "EC_KEY was not generated");
	BIO_set_flags(bio, BIO_FLAGS_WRITE);

	assert(PEM_write_bio_ECPrivateKey(bio, key, NULL, NULL, 0, NULL, NULL), "ECPrivateKey cannot be write");
	assert(PEM_write_bio_EC_PUBKEY(bio, key), "EC_PUBKEY cannot be write");

	BIO_free(bio);
}

static EVP_PKEY* EC_generate_key_v2() {
	EVP_PKEY* pkey = EVP_PKEY_new();

	//NID_secp521r1
	EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

	EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);
	assert(EC_KEY_generate_key(ec_key), "Could not generate key");

	assert(EVP_PKEY_assign_EC_KEY(pkey, ec_key), "Could not assign key");

	return pkey;
}

static EVP_PKEY* EC_generate_key_v1() {
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	assert(ctx, "Context cannot be created");

	//All this is to generate EVP_PKEY key properly
	assert(EVP_PKEY_paramgen_init(ctx), "ParamGen cannot be started");
	assert(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1), "Curve cannot be set");
	assert(EVP_PKEY_CTX_set_ec_param_enc(ctx, OPENSSL_EC_NAMED_CURVE), "Encoding cannot be set");

	//Creating a new key from filled context
	EVP_PKEY *paramgen_key = NULL;
	assert(EVP_PKEY_paramgen(ctx, &paramgen_key), "EVP_PKEY key cannot be created from context");

	//Creating a new context as we need to use their API's
	EVP_PKEY_CTX *keygen_ctx = EVP_PKEY_CTX_new(paramgen_key, NULL);
	assert(keygen_ctx, "ParamGen context cannot be created");
	assert(EVP_PKEY_keygen_init(keygen_ctx), "KeyGen cannot be started");
	EVP_PKEY *keygen_key = NULL;
	assert(EVP_PKEY_keygen(keygen_ctx, &keygen_key), "KeyGen key cannot be created");

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(paramgen_key);
	EVP_PKEY_CTX_free(keygen_ctx);

	return keygen_key;
}

static void MDECDSA_sign(EVP_PKEY* pkey, unsigned char* sig, unsigned long* sig_len, unsigned char* dig, unsigned long* dig_len) {
	EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
	//EVP_MD_CTX_init(md_ctx);

	assert(EVP_DigestSignInit(md_ctx, NULL, EVP_sha512(), NULL, pkey), "DigestSignInit could not be initialized");

	assert(EVP_DigestSignUpdate(md_ctx, sig, *sig_len), "DigestSignUpdate could not be performed");
	assert(EVP_DigestSignFinal(md_ctx, NULL, dig_len), "DigestSignFinal could not be performed");
	std::cout << "Buffer size: " << *dig_len << std::endl;

	assert(EVP_DigestSignFinal(md_ctx, dig, dig_len), "DigestSignFinal could not be performed");
	std::cout << "Buffer: " << dig << std::endl;

	EVP_MD_CTX_free(md_ctx);
}

static void MDECDSA_verify(EVP_PKEY* pkey, unsigned char* sig, unsigned long* sig_len, unsigned char* dig, unsigned long* dig_len) {
	EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
	//EVP_MD_CTX_init(md_ctx);

	assert(EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha512(), NULL, pkey), "DigestSignVerify could not be initialized");

	assert(EVP_DigestVerifyUpdate(md_ctx, sig, *sig_len), "DigestVerifyUpdate could not be performed");
	assert(EVP_DigestVerifyFinal(md_ctx, dig, *dig_len), "DigestVerifyFinal could not be performed");

	EVP_MD_CTX_free(md_ctx);
}

static void MDECDSA_start() {
	unsigned char in[] = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.";
	unsigned long in_len = sizeof(in);

	unsigned char buffer[4096] = {};
	unsigned long buffer_len = 0;

	EVP_PKEY* pkey = EC_generate_key_v2();
	assert(pkey, "EVP_PKEY could not be created");

	MDECDSA_sign(pkey, in, &in_len, buffer, &buffer_len);
	MDECDSA_verify(pkey, in, &in_len, buffer, &buffer_len);

	EC_write_key(EVP_PKEY_get0_EC_KEY(pkey));
	EVP_PKEY* read_pkey = EC_read_key();
	assert(read_pkey, "EC_read_key could not be performed");
	MDECDSA_verify(read_pkey, in, &in_len, buffer, &buffer_len);

	write_binary("data.bin", { buffer, buffer_len });
	BINARY_DATA binary_data = read_binary("data.bin");
	MDECDSA_verify(pkey, in, &in_len, binary_data.data, &binary_data.len);

	EVP_PKEY_free(pkey);
	EVP_PKEY_free(read_pkey);
	BINARY_DATA_free(binary_data);
}

void MDECDSA_example() {
	printf("Inicio de um sonho!\n");
	MDECDSA_start();
	printf("Deu tudo certo!\n");
}



