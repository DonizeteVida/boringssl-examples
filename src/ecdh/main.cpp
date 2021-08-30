#include "openssl/evp.h"
#include "openssl/pem.h"

#include "util.h"
#include "../sign/ECKeyRecover.h"

static void ECDH_test_encrypt(EVP_PKEY* pkey, unsigned char* sig, unsigned long* sig_len, unsigned char* dig, long dig_len) {
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
	assert(ctx, "Encrypt context is NULL");

	assert(EVP_PKEY_encrypt_init(ctx), "Encrypt sign cannot be started");

	assert(EVP_PKEY_encrypt(ctx, NULL, sig_len, dig, dig_len), "Signature size cannot be calculated");
	std::cout << "Digest length: " << *sig_len << std::endl;

	assert(EVP_PKEY_encrypt(ctx, sig, sig_len, dig, dig_len), "Signature cannot be transfered");

	std::cout << "Digest content: " << sig << std::endl;

	EVP_PKEY_CTX_free(ctx);
}

static void ECDH_test_decrypt(EVP_PKEY* pkey, unsigned char* out, unsigned long out_len, unsigned char* in, long in_len) {
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
	assert(ctx, "Encrypt context is NULL");

	assert(EVP_PKEY_decrypt_init(ctx), "Decrypt init cannot be performed");
	assert(EVP_PKEY_decrypt(ctx, out, &out_len, in, in_len), "Decrypt cannot be performed");

	EVP_PKEY_CTX_free(ctx);
}

static void ECDH_write_key(EC_KEY* ec_key) {
	//We'll write this key
	BIO* bio = BIO_new_file("key.pem", "w");

	assert(ec_key, "EC_KEY was not generated");
	BIO_set_flags(bio, BIO_FLAGS_WRITE);

	assert(PEM_write_bio_ECPrivateKey(bio, ec_key, NULL, NULL, 0, NULL, NULL), "ECPrivateKey cannot be write");
	assert(PEM_write_bio_EC_PUBKEY(bio, ec_key), "EC_PUBKEY cannot be write");

	BIO_free(bio);
}

static EVP_PKEY* ECDH_test_recover_key() {
	ECKeyRecover ecKeyRecover("key.pem");
	return ecKeyRecover();
}

static EVP_PKEY* ECDH_generate_key() {
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

static void ECDH_test_start() {

	unsigned char in[] = "Donizete Junior Ribeiro Vida";
	unsigned long in_len = sizeof(in);

	unsigned char buffer[2048];
	unsigned long buffer_len = 0;

	EVP_PKEY* pkey = ECDH_generate_key();

	ECDH_test_encrypt(pkey, buffer, &buffer_len, in, in_len);
	//in[in_len - 1] = 'A';
	ECDH_test_decrypt(pkey, buffer, buffer_len, in, in_len);

	ECDH_write_key(EVP_PKEY_get0_EC_KEY(pkey));
	EVP_PKEY* read_pkey = ECDH_test_recover_key();
	//in[in_len - 1] = 'A';
	ECDH_test_decrypt(read_pkey, buffer, buffer_len, in, in_len);


	EVP_PKEY_free(pkey);
	EVP_PKEY_free(read_pkey);
}

void ECDH_test() {
	printf("Inicio de um sonho\n");
	ECDH_test_start();
	printf("Deu tudo certo!\n");
}
