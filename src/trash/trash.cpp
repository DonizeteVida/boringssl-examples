#include "openssl/nid.h"
#include "openssl/ec.h"
#include "openssl/pem.h"
#include "openssl/x509.h"
#include "openssl/evp.h"

EVP_PKEY* generateECKey() {
	EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp384r1);
//	EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
//	if(!EC_KEY_set_group(key, group)) exit(0);
	EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);
	if (!EC_KEY_generate_key(key))
		exit(0);
	EVP_PKEY *pkey = EVP_PKEY_new();
	if (!EVP_PKEY_assign_EC_KEY(pkey, key))
		exit(0);
	//EC_KEY_free(key);
	return pkey;
}

void testECKEY() {
	EVP_PKEY *pkey = generateECKey();
	FILE *fp = fopen("key.pem", "wb");
	if (!PEM_write_PrivateKey(fp, pkey, nullptr, NULL, 0, NULL, NULL))
		exit(0);
	if (!PEM_write_PUBKEY(fp, pkey))
		exit(0);
}

void internetCode() {
	BIO *outbio = NULL;
	EC_KEY *myecc = NULL;
	EVP_PKEY *pkey = NULL;
	int eccgrp;

	/* ---------------------------------------------------------- *
	 * These function calls initialize openssl for correct work.  *
	 * ---------------------------------------------------------- */
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();

	/* ---------------------------------------------------------- *
	 * Create the Input/Output BIO's.                             *
	 * ---------------------------------------------------------- */
	outbio = BIO_new(BIO_s_file());
	outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

	/* ---------------------------------------------------------- *
	 * Create a EC key sructure, setting the group type from NID  *
	 * ---------------------------------------------------------- */
	eccgrp = OBJ_txt2nid("secp521r1");
	myecc = EC_KEY_new_by_curve_name(eccgrp);

	/* -------------------------------------------------------- *
	 * For cert signing, we use  the OPENSSL_EC_NAMED_CURVE flag*
	 * ---------------------------------------------------------*/
	EC_KEY_set_asn1_flag(myecc, OPENSSL_EC_NAMED_CURVE);

	/* -------------------------------------------------------- *
	 * Create the public/private EC key pair here               *
	 * ---------------------------------------------------------*/
	if (!(EC_KEY_generate_key(myecc)))
		BIO_printf(outbio, "Error generating the ECC key.");

	/* -------------------------------------------------------- *
	 * Converting the EC key into a PKEY structure let us       *
	 * handle the key just like any other key pair.             *
	 * ---------------------------------------------------------*/
	pkey = EVP_PKEY_new();
	if (!EVP_PKEY_assign_EC_KEY(pkey, myecc))
		BIO_printf(outbio, "Error assigning ECC key to EVP_PKEY structure.");

	/* -------------------------------------------------------- *
	 * Now we show how to extract EC-specifics from the key     *
	 * ---------------------------------------------------------*/
	myecc = EVP_PKEY_get1_EC_KEY(pkey);
	const EC_GROUP *ecgrp = EC_KEY_get0_group(myecc);

	/* ---------------------------------------------------------- *
	 * Here we print the key length, and extract the curve type.  *
	 * ---------------------------------------------------------- */
	BIO_printf(outbio, "ECC Key size: %d bit\n", EVP_PKEY_bits(pkey));
	BIO_printf(outbio, "ECC Key type: %s\n",
			OBJ_nid2sn(EC_GROUP_get_curve_name(ecgrp)));

	/* ---------------------------------------------------------- *
	 * Here we print the private/public key data in PEM format.   *
	 * ---------------------------------------------------------- */
	if (!PEM_write_bio_PrivateKey(outbio, pkey, NULL, NULL, 0, 0, NULL))
		BIO_printf(outbio, "Error writing private key data in PEM format");

	if (!PEM_write_bio_PUBKEY(outbio, pkey))
		BIO_printf(outbio, "Error writing public key data in PEM format");

	/* ---------------------------------------------------------- *
	 * Free up all structures                                     *
	 * ---------------------------------------------------------- */
	EVP_PKEY_free(pkey);
	EC_KEY_free(myecc);
	BIO_free_all(outbio);

	exit(0);
}
