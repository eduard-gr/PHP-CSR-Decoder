#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"

#include <openssl/opensslv.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <stdlib.h> //maloc

#define NAME_ONELINE_MAX    (1024 * 1024)


#define PHP_CSR_DECODER_VERSION "2.0"
#define PHP_CSR_DECODER_EXTNAME "ggssl"
 
extern zend_module_entry ggssl_module_entry;
#define phpext_ggssl_ptr &ggssl_module_entry

PHP_FUNCTION(csr_decoder);


/* Argument info for each function, used for reflection */
ZEND_BEGIN_ARG_INFO_EX(arginfo_csr_decoder, 0, 1, 0)
    ZEND_ARG_TYPE_INFO(0, str, IS_STRING, 1)
ZEND_END_ARG_INFO()

static const zend_function_entry functions[] = {
    PHP_FE(csr_decoder, arginfo_csr_decoder)
    PHP_FE_END
};


zend_module_entry ggssl_module_entry = {
    STANDARD_MODULE_HEADER,
    PHP_CSR_DECODER_EXTNAME,
    functions,
	NULL, // name of the MINIT function or NULL if not applicable
	NULL, // name of the MSHUTDOWN function or NULL if not applicable
	NULL, // name of the RINIT function or NULL if not applicable
	NULL, // name of the RSHUTDOWN function or NULL if not applicable
	NULL, // name of the MINFO function or NULL if not applicable
    PHP_CSR_DECODER_VERSION,
    STANDARD_MODULE_PROPERTIES
};


#if OPENSSL_VERSION_NUMBER > 268439904
#error "Open ssl version is too new"
#endif



int parse_san(zval* return_value, STACK_OF(X509_EXTENSION) *extensions){
	GENERAL_NAMES *sans = X509V3_get_d2i(extensions, NID_subject_alt_name, NULL, NULL);
	if(!sans){
		return 0;
	}
	
	int ii = sk_GENERAL_NAME_num(sans);
	if(ii <= 0){
		return 0;
	}

	zval names;
	array_init(&names);

	int i = 0;
	for(;i < ii; i++) {
		const GENERAL_NAME *current_name = sk_GENERAL_NAME_value(sans, i);
		if (current_name->type == GEN_DNS) {
			unsigned char *out;
			ASN1_STRING_to_UTF8(&out, current_name->d.dNSName);
			add_next_index_string(
				&names,
				out);
		}
	}

	add_assoc_zval(
		return_value,
		"san",
		&names);
}

int parse_extension(zval* return_value, X509_REQ *req){
	STACK_OF(X509_EXTENSION) *extensions;
	extensions = X509_REQ_get_extensions(req);
	if(!extensions) {
		return 0;
	}

	parse_san(return_value, extensions);
	return 0;
}

int parse_subject(zval* return_value, X509_REQ *req){
	X509_NAME *subject = X509_REQ_get_subject_name(req);
	if (subject == NULL){
		php_error_docref(NULL, E_NOTICE, "Unable to get subject");
		return 1;
	}

	int i = 0;
	int ii = X509_NAME_entry_count(subject);

	for(;i<ii;i++){
		X509_NAME_ENTRY *entry = X509_NAME_get_entry(subject, i);
		ASN1_OBJECT *obj       = X509_NAME_ENTRY_get_object(entry);
		ASN1_STRING *value     = X509_NAME_ENTRY_get_data(entry);
		
		int nid  = OBJ_obj2nid(obj);
		int type = value->type;
		int num  = value->length;

		if (num > NAME_ONELINE_MAX) {
			php_error_docref(NULL, E_NOTICE, "X509 r name too long");
			return 1;
		}

		zval dt;
		array_init(&dt);

		unsigned char *out;
		ASN1_STRING_to_UTF8(&out, value);
		
		add_assoc_long(
			&dt, 
			"type", 
			type);

		add_assoc_string(
			&dt,
			"value",
			out);

		add_assoc_zval(
			return_value,
			OBJ_nid2ln(nid),
			&dt);

	}

	return 0;
}

int parse_attributes(zval* return_value, X509_REQ *req){

	int ii = X509_REQ_get_attr_count(req);

	zval attributes;
	array_init(&attributes);

	int i;
	for (i = 0; i < ii; i++) {
		X509_ATTRIBUTE *attribute = X509_REQ_get_attr(req, i);

		int nid  = OBJ_obj2nid(X509_ATTRIBUTE_get0_object(attribute));

		if (X509_REQ_extension_nid(nid)){
			continue;
		}

		int jj = X509_ATTRIBUTE_count(attribute);
		
		zval values;
		array_init(&values);

		int j;
		for(j=0; j < jj; j++){
			ASN1_TYPE *at = X509_ATTRIBUTE_get0_type(attribute,j);

			ASN1_TYPE *type = at->type;
			ASN1_BIT_STRING *bs = at->value.bit_string;

			if ((type != V_ASN1_PRINTABLESTRING) &&
				(type != V_ASN1_T61STRING) &&
				(type != V_ASN1_IA5STRING)) {
				continue;
			}

			add_next_index_string(
				&values,
				(char *)bs->data);
		}

		add_assoc_zval(
			&attributes,
			OBJ_nid2ln(nid),
			&values);
	}


	add_assoc_zval(
		return_value,
		"attributes",
		&attributes);

}

void parse_version(zval* return_value, X509_REQ *req){


	if(req->req_info == NULL){
		add_assoc_null(return_value, "version");
		return;
	}

	if(req->req_info->version == NULL){
		add_assoc_null(return_value, "version");
		return;
	}

	int length = req->req_info->version->length;
	if(length == 0){
		add_assoc_null(return_value, "version");
		return;
	}

	long version = X509_REQ_get_version(req);

	add_assoc_long(
		return_value,
		"version",
		version);

	return;
}

int parse_signature(zval* return_value, X509_REQ *req){
	X509_ALGOR *sig_alg = req->sig_alg;
	if(sig_alg == NULL){
		php_error_docref(NULL, E_NOTICE, "Unable to get X509_ALGOR");
		return 1;
	}

	if(sig_alg->algorithm == NULL){
		php_error_docref(NULL, E_NOTICE, "Unable to get signature");
		return 1;
	}

	add_assoc_string(
		return_value,
		"signature",
		OBJ_nid2ln(OBJ_obj2nid(sig_alg->algorithm)));

	return 0;
}

int parse_pubkey(zval* return_value, X509_REQ *req){

	EVP_PKEY *pkey = X509_REQ_get_pubkey(req);

	if (pkey == NULL) {
		php_error_docref(NULL, E_NOTICE, "Unable to read EVP_PKEY");
		return 1;
	}

	add_assoc_string(
		return_value,
		"pubkey",
		OBJ_nid2ln(EVP_PKEY_id(pkey)));

	add_assoc_long(
		return_value,
		"bits",
		EVP_PKEY_bits(pkey));

	return 0;
}


ZEND_GET_MODULE(ggssl)
PHP_FUNCTION(csr_decoder){

	//printf("OPENSSL_VERSION_NUMBER:%ld",OPENSSL_VERSION_NUMBER);

	char *csr = NULL;
	size_t len;

	if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS(), "s", &csr, &len)) {
		php_error_docref(NULL, E_NOTICE, "Unable to parse parameters");
		RETURN_FALSE;
	}

	if(len < 1){
		php_error_docref(NULL, E_NOTICE, "CSR is empty");
		RETURN_FALSE;
	}

	array_init(return_value);

	BIO *bio = NULL;
	bio =  BIO_new(BIO_s_mem());

	if(BIO_write(bio, csr, len) == 0){
		BIO_free(bio);
		php_error_docref(NULL, E_NOTICE, "Unable to read BIO");
		RETURN_FALSE;
	}

	X509_REQ *req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
	if (req == NULL){
		BIO_free(bio);
		php_error_docref(NULL, E_NOTICE, "Unable to load X509 request");
		RETURN_FALSE;
	}

	parse_version(return_value, req);

	if(parse_signature(return_value, req) != 0){
		BIO_free(bio);
		X509_REQ_free(req);
		php_error_docref(NULL, E_NOTICE, "Unable to read signature");
		RETURN_FALSE;
	}

	if(parse_pubkey(return_value, req) != 0){
		BIO_free(bio);
		X509_REQ_free(req);
		php_error_docref(NULL, E_NOTICE, "Unable to read evp pkey");
		RETURN_FALSE;
	}

	if(parse_subject(return_value, req) != 0){
		BIO_free(bio);
		X509_REQ_free(req);
		php_error_docref(NULL, E_NOTICE, "Unable to read subject");
		RETURN_FALSE;
	}

	if(parse_attributes(return_value, req) != 0){
		BIO_free(bio);
		X509_REQ_free(req);
		php_error_docref(NULL, E_NOTICE, "Unable to read attributes");
		RETURN_FALSE;
	}

	if(parse_extension(return_value, req) != 0){
		BIO_free(bio);
		X509_REQ_free(req);
		php_error_docref(NULL, E_NOTICE, "Unable to read subject");
		RETURN_FALSE;
	}

	BIO_free(bio);
	X509_REQ_free(req);

}
