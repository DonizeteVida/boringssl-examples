/*
 * main.cpp
 *
 *  Created on: Sep 7, 2021
 *      Author: doni
 */

#include <string.h>

#include "openssl/evp.h"
#include "openssl/ec.h"
#include "openssl/digest.h"
#include "openssl/nid.h"
#include "openssl/bio.h"
#include "openssl/pem.h"

#include "util.h"

static EVP_PKEY* EC_read_key() {
	BIO *bio = BIO_new_file("key.pem", "r");

	assert(bio);

	EC_KEY *ec_key = NULL;

	assert(PEM_read_bio_ECPrivateKey(bio, &ec_key, NULL, NULL));
	assert(PEM_read_bio_EC_PUBKEY(bio, &ec_key, NULL, NULL));

	BIO_free(bio);

	EVP_PKEY *pkey = EVP_PKEY_new();
	assert(EVP_PKEY_set1_EC_KEY(pkey, ec_key));

	return pkey;
}

static void EC_write_key(EC_KEY *key) {
	BIO *bio = BIO_new_file("key.pem", "w");

	assert(bio);
	BIO_set_flags(bio, BIO_FLAGS_WRITE);

	assert(PEM_write_bio_ECPrivateKey(bio, key, NULL, NULL, 0, NULL, NULL));
	assert(PEM_write_bio_EC_PUBKEY(bio, key));

	BIO_free(bio);
}

static void EVP_PKEY_write_private_key(EVP_PKEY* pkey) {
	BIO *bio = BIO_new_file("priv_key.pem", "w");

	assert(bio);
	BIO_set_flags(bio, BIO_FLAGS_WRITE);

	assert(PEM_write_bio_PKCS8PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL));

	BIO_free(bio);
}

static void EVP_PKEY_write_public_key(EVP_PKEY* pkey) {
	BIO *bio = BIO_new_file("pub_key.pem", "w");

	assert(bio);
	BIO_set_flags(bio, BIO_FLAGS_WRITE);

	X509* x509 = X509_new();

	assert(X509_set_pubkey(x509, pkey));
	assert(X509_sign(x509, pkey, EVP_sha512()));

	X509_NAME* name = X509_get_subject_name(x509);

	char *codes[] = {
			"CN",
			"O",
			"OU",
			"L",
			//"S",
			//"C"
	};

	char *values[] = {
			"Common name",
			"Organization",
			"Organization Unit",
			"Locality",
			//"State",
			//"Country"
	};

	for (int i = 0; i < 4; i++) {
		char* code = codes[i];
		char* value = values[i];
		assert(X509_NAME_add_entry_by_txt(name, code,  MBSTRING_ASC, (unsigned char*) value, strlen(value), -1, 0));
	}

	//Because Java throws an exception when reading it
	//Empty issuer DN not allowed in X509Certificates
	assert(X509_set_issuer_name(x509, name));

	//Because Java throws an exception when reading it
	//Invalid encoding for CertificateValidity
	assert(X509_gmtime_adj(X509_get_notBefore(x509), 0))
	assert(X509_gmtime_adj(X509_get_notAfter(x509), 31536000L));

	assert(PEM_write_bio_X509(bio, x509));

	BIO_free(bio);
}

static EVP_PKEY* EC_generate_key_v2() {
	EVP_PKEY* pkey = EVP_PKEY_new();

	//NID_secp521r1
	EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

	EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);
	assert(EC_KEY_generate_key(ec_key));

	assert(EVP_PKEY_assign_EC_KEY(pkey, ec_key));

	return pkey;
}

static EVP_PKEY* EC_generate_key_v1() {
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	assert(ctx);

	//All this is to generate EVP_PKEY key properly
	assert(EVP_PKEY_paramgen_init(ctx));
	assert(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1));
	assert(EVP_PKEY_CTX_set_ec_param_enc(ctx, OPENSSL_EC_NAMED_CURVE));

	//Creating a new key from filled context
	EVP_PKEY *paramgen_key = NULL;
	assert(EVP_PKEY_paramgen(ctx, &paramgen_key));

	//Creating a new context as we need to use their API's
	EVP_PKEY_CTX *keygen_ctx = EVP_PKEY_CTX_new(paramgen_key, NULL);
	assert(keygen_ctx);
	assert(EVP_PKEY_keygen_init(keygen_ctx));
	EVP_PKEY *keygen_key = NULL;
	assert(EVP_PKEY_keygen(keygen_ctx, &keygen_key));

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(paramgen_key);
	EVP_PKEY_CTX_free(keygen_ctx);

	return keygen_key;
}

static void MDECDSA_sign(EVP_PKEY* pkey, unsigned char* sig, unsigned long* sig_len, unsigned char* dig, unsigned long* dig_len) {
	EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
	//EVP_MD_CTX_init(md_ctx);

	assert(EVP_DigestSignInit(md_ctx, NULL, EVP_sha512(), NULL, pkey));

	assert(EVP_DigestSignUpdate(md_ctx, sig, *sig_len));
	assert(EVP_DigestSignFinal(md_ctx, NULL, dig_len));
	std::cout << "Buffer size: " << *dig_len << std::endl;

	assert(EVP_DigestSignFinal(md_ctx, dig, dig_len));
	std::cout << "Buffer: " << dig << std::endl;

	EVP_MD_CTX_free(md_ctx);
}

static void MDECDSA_verify(EVP_PKEY* pkey, unsigned char* sig, unsigned long* sig_len, unsigned char* dig, unsigned long* dig_len) {
	EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
	//EVP_MD_CTX_init(md_ctx);

	assert(EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha512(), NULL, pkey));

	assert(EVP_DigestVerifyUpdate(md_ctx, sig, *sig_len));
	assert(EVP_DigestVerifyFinal(md_ctx, dig, *dig_len));

	EVP_MD_CTX_free(md_ctx);
}

static void MDECDSA_start() {
	unsigned char in[] = "My cool data";
	//-1 because we can ignore \0 on digest signature
	unsigned long in_len = sizeof(in) - 1;

	unsigned char buffer[4096] = {};
	unsigned long buffer_len = 0;

	EVP_PKEY* pkey = EC_generate_key_v2();
	assert(pkey);

	MDECDSA_sign(pkey, in, &in_len, buffer, &buffer_len);
	MDECDSA_verify(pkey, in, &in_len, buffer, &buffer_len);

	EC_write_key(EVP_PKEY_get0_EC_KEY(pkey));
	EVP_PKEY* read_pkey = EC_read_key();
	assert(read_pkey);
	MDECDSA_verify(read_pkey, in, &in_len, buffer, &buffer_len);

	write_binary("data.bin", { buffer, buffer_len });
	BINARY_DATA binary_data = read_binary("data.bin");
	MDECDSA_verify(pkey, in, &in_len, binary_data.data, &binary_data.len);

	EVP_PKEY_write_private_key(pkey);
	EVP_PKEY_write_public_key(pkey);

	EVP_PKEY_free(pkey);
	EVP_PKEY_free(read_pkey);
	BINARY_DATA_free(binary_data);
}

void MDECDSA_example() {
	printf("Inicio de um sonho!\n");
	MDECDSA_start();
	printf("Deu tudo certo!\n");
}



