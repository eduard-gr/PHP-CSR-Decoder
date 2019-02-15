#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"


#include <openssl/bio.h>
#include <openssl/x509.h> //dekoder
#include <openssl/x509v3.h>

#include <openssl/pem.h>

//#include <stdio.h>
//#include <endian.h>

//#include <string.h> //memset
#include <stdlib.h> //maloc


#define NAME_ONELINE_MAX    (1024 * 1024)


#define PHP_MY_EXTENSION_VERSION "1.0"
#define PHP_MY_EXTENSION_EXTNAME "ggssl"
 
extern zend_module_entry ggssl_module_entry;
#define phpext_ggssl_ptr &ggssl_module_entry

PHP_FUNCTION(csr_decoder);

const zend_function_entry functions[] = {
	PHP_FE(csr_decoder, NULL)
	{NULL, NULL, NULL}
};
 
// the following code creates an entry for the module and registers it with Zend.
zend_module_entry ggssl_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	PHP_MY_EXTENSION_EXTNAME,
	functions,
	NULL, // name of the MINIT function or NULL if not applicable
	NULL, // name of the MSHUTDOWN function or NULL if not applicable
	NULL, // name of the RINIT function or NULL if not applicable
	NULL, // name of the RSHUTDOWN function or NULL if not applicable
	NULL, // name of the MINFO function or NULL if not applicable
#if ZEND_MODULE_API_NO >= 20010901
	PHP_MY_EXTENSION_VERSION,
#endif
	STANDARD_MODULE_PROPERTIES
};


int parse_san(zval* return_value, STACK_OF(X509_EXTENSION) *extensions){
	GENERAL_NAMES *sans = X509V3_get_d2i(extensions, NID_subject_alt_name, NULL, NULL);
	if(!sans){
		return 0;
	}
	
	int ii = sk_GENERAL_NAME_num(sans);
	if(ii <= 0){
		return 0;
	}

	zval* names;
	MAKE_STD_ZVAL(names);
	array_init(names);

	for (int i = 0; i < ii; i++) {
		const GENERAL_NAME *current_name = sk_GENERAL_NAME_value(sans, i);
		if (current_name->type == GEN_DNS) {
			add_next_index_string(
				names,
				ASN1_STRING_data(current_name->d.dNSName),
				1);
		}
	}
	
	add_assoc_zval(return_value, "san", names);
}

int parse_extension(zval* return_value, X509_REQ *req){
	STACK_OF(X509_EXTENSION) *extensions;
	extensions = X509_REQ_get_extensions(req);
	if(!extensions) {
		return 0;
	}
	parse_san(return_value, extensions);
	sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
	return 0;
}

int parse_subject(zval* return_value, X509_REQ *req){

	X509_NAME *subject = X509_REQ_get_subject_name(req);
	if (subject == NULL){
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unable to get subject");
		return 1;
	}

	for(int i=0,ii=X509_NAME_entry_count(subject);i<ii;i++){
		X509_NAME_ENTRY *entry = X509_NAME_get_entry(subject, i);
		ASN1_OBJECT *obj       = X509_NAME_ENTRY_get_object(entry);
		ASN1_STRING *value     = X509_NAME_ENTRY_get_data(entry);

		int nid = OBJ_obj2nid(obj);
		int type = value->type;
		int num = value->length;

		if (num > NAME_ONELINE_MAX) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "X509 r name too long");
			return 1;
		}

		zval* dt;
		MAKE_STD_ZVAL(dt);
		array_init(dt);

		//add_assoc_long(dt, "nid", nid);
		add_assoc_long(dt, "type", type);
		//add_assoc_long(dt, "length", num);
		add_assoc_string(
			dt,
			"value",
			ASN1_STRING_get0_data(value),
			num);

		add_assoc_zval(
			return_value,
			OBJ_nid2ln(nid),
			dt);
	}

	return 0;
}


int parse_signature(zval* return_value, X509_REQ *req){

	const X509_ALGOR *sig_alg;
	X509_REQ_get0_signature(req, NULL, &sig_alg);
	if(sig_alg == NULL){
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unable to read X509_ALGOR");
		return 1;
	}

	const ASN1_OBJECT *obj;
	X509_ALGOR_get0(&obj, NULL, NULL, sig_alg);

	if(obj == NULL) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unable to read X509_ALGOR");
		return 1;
	}

	int nid = OBJ_obj2nid(obj);
	add_assoc_string(
		return_value,
		"signature",
		OBJ_nid2ln(nid),
		strlen(OBJ_nid2ln(nid)));

	return 0;
}



int parse_pubkey(zval* return_value, X509_REQ *req){

	EVP_PKEY *pkey = X509_REQ_get0_pubkey(req);
	if (pkey == NULL) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unable to read EVP_PKEY");
		return 1;
	}

	add_assoc_string(
		return_value,
		"pubkey",
		OBJ_nid2ln(EVP_PKEY_id(pkey)),
		strlen(OBJ_nid2ln(EVP_PKEY_id(pkey))));

	add_assoc_long(
		return_value,
		"bits",
		EVP_PKEY_bits(pkey));

	EVP_PKEY_free(pkey);
	return 0;
}


ZEND_GET_MODULE(ggssl)
PHP_FUNCTION(csr_decoder){
	char *csr;
	int len;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &csr, &len)) {
		RETURN_FALSE;
	}
	
	if(len < 1){
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "CSR is empty.");
		RETURN_FALSE;
	}

	array_init(return_value);

	BIO *bio = NULL;
	bio =  BIO_new(BIO_s_mem());
	if(BIO_write(bio, csr, len) == 0){
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unable to read BIO");
		RETURN_FALSE;
	}

	X509_REQ *req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
	if (req == NULL){
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unable to load X509 request");
		RETURN_FALSE;
	}

	if(parse_signature(return_value, req) != 0){
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unable to read signature");
		RETURN_FALSE;
	}

	if(parse_pubkey(return_value, req) != 0){
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unable to read evp pkey");
		RETURN_FALSE;
	}

	if(parse_subject(return_value, req) != 0){
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unable to read subject");
		RETURN_FALSE;
	}

	if(parse_extension(return_value, req) != 0){
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unable to read subject");
		RETURN_FALSE;
	}

	X509_REQ_free(req);
	BIO_free(bio);
}
