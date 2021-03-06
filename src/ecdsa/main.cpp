#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/base.h"

#include "util.h"

#include <string.h>
#include <iostream>

static void ECDSA_test_sign(EVP_PKEY *pkey, unsigned char *sig, unsigned long *sig_len, unsigned char *dig, long dig_len) {
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
	assert(ctx);

	assert(EVP_PKEY_sign_init(ctx));
	assert(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha1()));

	assert(EVP_PKEY_sign(ctx, NULL, sig_len, dig, dig_len));
	std::cout << "Digest length: " << *sig_len << std::endl;

	assert(EVP_PKEY_sign(ctx, sig, sig_len, dig, dig_len));

	std::cout << "Digest content: " << sig << std::endl;

	EVP_PKEY_CTX_free(ctx);
}

static void ECDSA_test_verify(EVP_PKEY *pkey, unsigned char *sig, unsigned long sig_len, unsigned char *dig, long dig_len) {
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
	assert(ctx);
	assert(EVP_PKEY_verify_init(ctx));

	int result = EVP_PKEY_verify(ctx, sig, sig_len, dig, dig_len);
	if (result) {
		std::cout << "Data is okay" << std::endl;
	} else {
		std::cerr << "Data isn't okay" << std::endl;
	}
	EVP_PKEY_CTX_free(ctx);
}

static void ECDSA_write_key(EC_KEY *ec_key) {
	//We'll write this key
	BIO *bio = BIO_new_file("key.pem", "w");

	assert(ec_key);
	BIO_set_flags(bio, BIO_FLAGS_WRITE);

	assert(PEM_write_bio_ECPrivateKey(bio, ec_key, NULL, NULL, 0, NULL, NULL));
	assert(PEM_write_bio_EC_PUBKEY(bio, ec_key));

	BIO_free(bio);
}

static EVP_PKEY* ECDSA_test_recover_key() {
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

static EVP_PKEY* ECDSA_generate_key() {
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	assert(ctx);

	//All this is to generate EVP_PKEY key properly
	assert(EVP_PKEY_paramgen_init(ctx));
	assert(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp521r1));
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

static X509* EVP_PKEY_to_X509(EVP_PKEY *pkey) {
	X509 *x509 = X509_new();

	//assert(X509_set_pubkey(x509, pkey), "We cannot set pub key");
	assert(X509_sign(x509, pkey, EVP_sha256()));

	return x509;
}

static EVP_PKEY* X509_to_EVP_PKEY(X509* x509) {
	return X509_get_pubkey(x509);
}

static EVP_PKEY* EVP_PKEY_read_x509() {
	BIO *bio = BIO_new_file("x509.pem", "r");
	assert(bio);

	X509 *x509 = NULL;

	assert(PEM_read_bio_X509(bio, &x509, NULL, NULL));

	BIO_free(bio);

	EVP_PKEY *pkey = EVP_PKEY_new();

	return pkey;
}

static void ECDSA_test_start() {

	unsigned char in[] = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.";
	unsigned long in_len = sizeof(in);

	unsigned char buffer[4096];
	unsigned long buffer_len = 0;

	EVP_PKEY *pkey = ECDSA_generate_key();

	ECDSA_test_sign(pkey, buffer, &buffer_len, in, in_len);
	//in[in_len - 1] = 'A';
	ECDSA_test_verify(pkey, buffer, buffer_len, in, in_len);

	ECDSA_write_key(EVP_PKEY_get0_EC_KEY(pkey));
	EVP_PKEY *read_pkey = ECDSA_test_recover_key();
	//in[in_len - 1] = 'A';
	ECDSA_test_verify(read_pkey, buffer, buffer_len, in, in_len);

//	X509* x509 = EVP_PKEY_to_X509(pkey);
//	EVP_PKEY* x509_pkey = X509_to_EVP_PKEY(x509);
//	EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(x509_pkey);
//
//	const EC_POINT* publicKey =  EC_KEY_get0_public_key(ec_key);
//	const BIGNUM* privateKey = EC_KEY_get0_private_key(ec_key);
//
//	ECDSA_test_verify(x509_pkey, buffer, buffer_len, in, in_len);
//	//ECDSA_test_sign(x509_pkey, buffer, &buffer_len, in, in_len);

	EVP_PKEY_free(pkey);
	EVP_PKEY_free(read_pkey);
}

void ECDSA_test() {
	printf("Inicio de um sonho\n");
	ECDSA_test_start();
	printf("Deu tudo certo!\n");
}

