//gcc read-test.c -o read-test -I /usr/include/openssl -lcrypto -Wall

#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

#include <stdlib.h> //maloc
#include <string.h>

#define NAME_ONELINE_MAX    (1024 * 1024)

//268439904
#if OPENSSL_VERSION_NUMBER > 268439904
#error "Open ssl version is too new"
#endif

int parse_san(STACK_OF(X509_EXTENSION) *extensions){
	GENERAL_NAMES *sans = X509V3_get_d2i(extensions, NID_subject_alt_name, NULL, NULL);
	if(!sans){
		return 0;
	}
	
	int ii = sk_GENERAL_NAME_num(sans);
	if(ii <= 0){
		return 0;
	}

	int i = 0;
	for(;i < ii; i++) {
		const GENERAL_NAME *current_name = sk_GENERAL_NAME_value(sans, i);
		if (current_name->type == GEN_DNS) {
			unsigned char *out;
			ASN1_STRING_to_UTF8(&out, current_name->d.dNSName);
			
			printf("parse_san %s\n",out);
		}
	}
}

int parse_extension(X509_REQ *req){

	STACK_OF(X509_EXTENSION) *extensions;
	extensions = X509_REQ_get_extensions(req);

	if(!extensions) {
		return 0;
	}

	parse_san(extensions);
	return 0;
}

int parse_subject(X509_REQ *req){

	X509_NAME *subject = X509_REQ_get_subject_name(req);
	if (subject == NULL){
		printf("Unable to get subject\n");
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
			printf("X509 r name too long\n");
			return 1;
		}

		unsigned char *out;
		ASN1_STRING_to_UTF8(&out, value);
		

		printf("subject-%d %d %s\n",
			i,
			type,
			out);
	}

	return 0;
}


int parse_attributes(X509_REQ *req){

	int ii = X509_REQ_get_attr_count(req);

	int i;
	for (i = 0; i < ii; i++) {
		X509_ATTRIBUTE *attribute = X509_REQ_get_attr(req, i);

		int nid  = OBJ_obj2nid(X509_ATTRIBUTE_get0_object(attribute));

		if (X509_REQ_extension_nid(nid)){
			continue;
		}

		int jj = X509_ATTRIBUTE_count(attribute);

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

			printf("attribute-%d %s\n",
				i,
				(char *)bs->data);
		}
	}

	return 0;
}


void parse_version(X509_REQ *req){


	if(req->req_info == NULL){
		printf("version is null\n");
		return;
	}

	if(req->req_info->version == NULL){
		printf("version is null\n");
		return;
	}

	int length = req->req_info->version->length;
	if(length == 0){
		printf("version is null\n");
		return;
	}

	long version = X509_REQ_get_version(req);

	printf("version %ld \n",
		version);

	return;
}

int parse_signature(X509_REQ *req){
	X509_ALGOR *sig_alg = req->sig_alg;
	if(sig_alg == NULL){
		printf("Unable to get X509_ALGOR\n");
		return 1;
	}

	if(sig_alg->algorithm == NULL){
		printf("Unable to get signature\n");
		return 1;
	}

	printf("signature %s\n",
		OBJ_nid2ln(OBJ_obj2nid(sig_alg->algorithm)));

	return 0;
}

int parse_pubkey(X509_REQ *req){

	EVP_PKEY *pkey = X509_REQ_get_pubkey(req);

	if (pkey == NULL) {
		printf("Unable to read EVP_PKEY\n");
		return 1;
	}


	printf("pubkey %s\n",
		OBJ_nid2ln(EVP_PKEY_id(pkey)));

	printf("bits %d\n",
		EVP_PKEY_bits(pkey));

	return 0;
}

int main(int argc, char *argv[]){

	printf("OPENSSL_VERSION_NUMBER:%ld\n", OPENSSL_VERSION_NUMBER);

	char *csr = "-----BEGIN CERTIFICATE REQUEST-----\n\
MIICwjCCAaoCADB+MQswCQYDVQQGEwJVQTETMBEGA1UEAxMKY2ltYm9yLm5ldDES\n\
MBAGA1UEBxMJTXVrYWNoZXZvMRcwFQYDVQQKEw5DaW1ib3IgTmV0d29yazEbMBkG\n\
A1UECBMSWmFrYXJwYXR0aWEgT2JsYXN0MRAwDgYDVQQLEwdzdXBwb3J0MIIBIjAN\n\
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq1Fz+CTCEYB0t+NZ+oQtyjQ/PdTO\n\
yT+WGO69cl+JLPKqkNRXApJNff5oYZtDsfl4o6n42OVcl0SUjjGGhidQbOlUKSb3\n\
trvYI5+EBW+1NnPaoghsDkhAFDz2rLT2LTJ8cOsgErZpI83CSJ85Nwr/MKV085gr\n\
BSVYWasbCbKSDfMA/M2C7By9pvmwZAUSHLiVGnSC/4eEEQIWhADheKhZsZrNMLxq\n\
rcXxSygZ2DSwxA8ckoIUzXrhSQzDUMzYh6p2y13Z6g3QXHeAC66WygBhhiyMIFiz\n\
Q5ikXfEh1jNTzSCE0KJBoTOpEETZmPoj2I6uWy7gV6P++5xNPjGqoaLXcQIDAQAB\n\
oAAwDQYJKoZIhvcNAQELBQADggEBAD5F+hU5UR6CZqhQPBuRsJUke6pgMqVgM7RQ\n\
6tck2z/LrPcKbUDlIbrGHnrCqEmorsSneFphPlMSgpGqRM/O8xnvVoUWrThjhwtb\n\
33hgNe9obJaciIZnh2qLgmO0N8rBPZvwDGaZQlIyNVEeT3NLBxH3PGSmawwUsN0T\n\
wXks0OVO8Q9nFmEh+wiY5tjJF6bUVkzuzlMqfStFJAUHqma7wRqtQZwS4HIiasq5\n\
Mpm7xQkrFxatonG8wDqydNUpYdMTDAPfs/onGULkrP1LxmYdGwGpDWx6+P8uiIIt\n\
ZOjZ4dgH6AU1chaRbNUoxAF1Ayi4/iL/Ec9zyXJzUxJ66PJD5M4=\n\
-----END CERTIFICATE REQUEST-----";

	BIO* bio = NULL;
	bio =  BIO_new(BIO_s_mem());
	int len = strlen(csr);
	if(BIO_write(bio, csr, len) == 0){
		printf("Unable to read BIO\n");
		return 1;
	}

	X509_REQ *req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
	if (req == NULL){
		printf("Unable to load X509 request\n");
		return 1;
	}

	parse_version(req);

	if(parse_signature(req) != 0){
		BIO_free(bio);
		X509_REQ_free(req);
		printf("Unable to read signature\n");
		return 1;
	}

	if(parse_pubkey(req) != 0){
		BIO_free(bio);
		X509_REQ_free(req);
		printf("Unable to read evp pkey\n");
		return 1;
	}

	if(parse_subject(req) != 0){
		BIO_free(bio);
		X509_REQ_free(req);
		printf("Unable to read subject\n");
		return 1;
	}

	if(parse_attributes(req) != 0){
		BIO_free(bio);
		X509_REQ_free(req);
		printf("Unable to read attributes\n");
		return 1;
	}

	if(parse_extension(req) != 0){
		BIO_free(bio);
		X509_REQ_free(req);
		printf("Unable to read subject\n");
		return 1;
	}


	X509_REQ_free(req);
	BIO_free(bio);
}
