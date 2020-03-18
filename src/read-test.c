//gcc read-test.c -o read-test -I /usr/include/openssl -lcrypto -Wall
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <stdlib.h> //maloc


#define NAME_ONELINE_MAX    (1024 * 1024)

#if OPENSSL_VERSION_NUMBER > 268443839
#define OPENSSL_11X
#endif



void printhex(unsigned char *in, int len){
	int i = 0;
	for(; i < len; i ++) {
		printf(" %2x(%d)", in[i], in[i]);
	}
	printf("\n");
}

int parse_san(zval* return_value, STACK_OF(X509_EXTENSION) *extensions){
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
			printf("san:%s\n",out);
		}

	}
	return 0;
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
		printf("Unable to get subject\n");
		return 1;
	}

	int i = 0;
	int ii = X509_NAME_entry_count(subject);
	for(;i<ii;i++){
		X509_NAME_ENTRY *entry = X509_NAME_get_entry(subject, i);
		ASN1_OBJECT *obj       = X509_NAME_ENTRY_get_object(entry);
		ASN1_STRING *value     = X509_NAME_ENTRY_get_data(entry);

		int nid = OBJ_obj2nid(obj);
		int type = value->type;
		int length = value->length;

		if (length > NAME_ONELINE_MAX) {
			printf("X509 r name too long\n");
			return 1;
		}

		unsigned char *out;
		ASN1_STRING_to_UTF8(&out, value);

		printf("%s - type:%d length:%d value:%s \n value:%s \n",
			OBJ_nid2ln(nid),
			type,
			length,
			//Unfortunately for backward compatibility we need to use DEPRECATED version.
			//ASN1_STRING_get0_data(value)
			ASN1_STRING_data(value),
			out
		);

/*
		traverse_string(
			ASN1_STRING_data(value),
			length,
			type,
			out_utf8,
		);
		ASN1_mbstring_copy
*/
/*
		printf("%s - type:%d length:%d value:%s \n",
			OBJ_nid2ln(nid),
			type,
			length,
			//Unfortunately for backward compatibility we need to use DEPRECATED version.
			//ASN1_STRING_get0_data(value)
			asn1_utf8(ASN1_STRING_data(value))
		);
		*/
		
/*
		unsigned char *dt = ASN1_STRING_data(value);
		unsigned char *utf8 = malloc(length);
		ch2utf8(dt, utf8);
		printf("%s\n",utf8);
		printhex(ASN1_STRING_data(value), length);
*/
	}

	return 0;
}


int parse_signature(zval* return_value, X509_REQ *req){
	/*
	const X509_ALGOR *sig_alg;
	X509_REQ_get0_signature(req, NULL, &sig_alg);
	if(sig_alg == NULL){
		printf("Unable to read X509_ALGOR\n");
		return 1;
	}

	const ASN1_OBJECT *obj;
	X509_ALGOR_get0(&obj, NULL, NULL, sig_alg);

	if(obj == NULL) {
		printf("Unable to read X509_ALGOR\n");
		return 1;
	}

	int nid = OBJ_obj2nid(obj);
	printf("signature: %s\n",
		OBJ_nid2ln(nid));
	*/

#ifdef OPENSSL_11X
	printf("signature: %s\n",
		OBJ_nid2ln(X509_REQ_get_signature_nid(req)));
#else
//Unfortunately for backward compatibility we need to use OLD version.
	X509_ALGOR *sig_alg = req->sig_alg;
	if(sig_alg == NULL){
		printf("Unable to get X509_ALGOR\n");
		return 1;
	}

	if(sig_alg->algorithm == NULL){
		printf("Unable to get signature\n");
		return 1;
	}

	printf("signature: %s\n",
		OBJ_nid2ln(OBJ_obj2nid(sig_alg->algorithm))
	);
#endif

	return 0;
}



int parse_pubkey(zval* return_value, X509_REQ *req){

#ifdef OPENSSL_11X
	EVP_PKEY *pkey = X509_REQ_get0_pubkey(req);
#else
	//Unfortunately for backward compatibility we need to use DEPRECATED version.
	EVP_PKEY *pkey = X509_REQ_get_pubkey(req);
#endif

	EVP_PKEY *pkey = X509_REQ_get_pubkey(req);
	if (pkey == NULL) {
		printf("Unable to read EVP_PKEY\n");
		return 1;
	}

	printf("pubkey:%s bits:%d\n",
		OBJ_nid2ln(EVP_PKEY_id(pkey)),
		EVP_PKEY_bits(pkey));

	return 0;
}


int main(int argc, char *argv[]){

	printf("OPENSSL_VERSION_NUMBER:%ld\n", OPENSSL_VERSION_NUMBER);

	zval* return_value = NULL;
	BIO* bio = NULL;
	bio = BIO_new(BIO_s_file());
	if(BIO_read_filename(bio, argv[1]) == 0){
		printf("Unable to read BIO\n");
		return 1;
	}

	
	/*

	char *csr = "-----BEGIN CERTIFICATE REQUEST-----\n\
MIIEeTCCA2ECAQAwfDEkMCIGA1UEAwwbZXhtYWlsLmFsYXNrYW5jcmFiY28uY29t\n\
LmF1MQ4wDAYDVQQLDAVBZG1pbjEYMBYGA1UECgwPQWxhc2thbiBDcmFiIENvMQ8w\n\
DQYDVQQHDAZTeWRuZXkxDDAKBgNVBAgMA05TVzELMAkGA1UEBhMCQVUwggEiMA0G\n\
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCNtnluvziE9Hf7/aw4V/PfcFD1l5Rw\n\
jWYOAjwmU4blaBK5zNxwlZIvMSuNP46xqA43CPyHZABsbvHPBKSY2NYb5mu/TttS\n\
gki60bZ/jUwaF7DotT78cfun7aUXVYsER7OrGEuKYBIsm8A6CbLyw+djo2+lEoUM\n\
ozllSzYVN9k/v7t368skf9XFEf/KFqeUYtiFmRzDmNwyYen4vi+assnRz8wVT+Aa\n\
cTlYT72L6oQ3SH+RnlPbdhDvx3D4NoXKmnktqVtHBfwQAZExJNiYlm6CkbaVnEdM\n\
zXQJg5Wc43e+Feho7oYc2WB2HUpRjb2FHyiwbuCfSDC1a9uMatdDc5mnAgMBAAGg\n\
ggG2MBoGCisGAQQBgjcNAgMxDBYKNi4yLjkyMDAuMjBrBgkrBgEEAYI3FRQxXjBc\n\
AgEFDCFTUlYtTUFJTC5zeWQuYWxhc2thbmNyYWJjby5jb20uYXUMEEFLS1NZRFxT\n\
UlYtTUFJTCQMIk1pY3Jvc29mdC5FeGNoYW5nZS5TZXJ2aWNlSG9zdC5leGUwcgYK\n\
KwYBBAGCNw0CAjFkMGICAQEeWgBNAGkAYwByAG8AcwBvAGYAdAAgAFIAUwBBACAA\n\
UwBDAGgAYQBuAG4AZQBsACAAQwByAHkAcAB0AG8AZwByAGEAcABoAGkAYwAgAFAA\n\
cgBvAHYAaQBkAGUAcgMBADCBtgYJKoZIhvcNAQkOMYGoMIGlMA4GA1UdDwEB/wQE\n\
AwIFoDBmBgNVHREEXzBdghtleG1haWwuYWxhc2thbmNyYWJjby5jb20uYXWCIUF1\n\
dG9EaXNjb3Zlci5hbGFza2FuY3JhYmNvLmNvbS5hdYIbcmVtb3RlLmFsYXNrYW5j\n\
cmFiY28uY29tLmF1MAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFOxydPyynZeL1f5H\n\
sd3Ka52mtdAZMA0GCSqGSIb3DQEBBQUAA4IBAQBw8qOYwdLwqXPY7yIwwtE8eX4P\n\
MSxn/HGC05hWn1/ztuLYzUZHOkCIQpPh2AjFe0JYuWIOhC59DT/fx7uZA1sdLdCe\n\
tzeRLJ0D61I4NJo2BIAa05sctH856Spn0/atF8DKHlKZl/8hpQCfSjOliTDeVoKh\n\
OwajwTJ0QBEmO4NxT8DdbRkmmJr1rop0f/NUyJXSeE4vAy3+nT2TnmcLbQiyDdce\n\
QwVMS10o+FQWlU6GOrvNGeRxCTkqubyI4I+XwysJJZYdon3LUyOeHXJZWTsUPaIp\n\
BkL7GlTH86DJU4eKVguIule9w5lekpWA4UF0fDOfrX2M92cCcwnd/GUuyKE6\n\
-----END CERTIFICATE REQUEST-----";


	bio =  BIO_new(BIO_s_mem());
	int len = strlen(csr);
	if(BIO_write(bio, csr, len) == 0){
		printf("Unable to read BIO\n");
		return 1;
	}
	*/

	X509_REQ *req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
	if (req == NULL){
		printf("Unable to load X509 request\n");
		return 1;
	}

	if(parse_signature(return_value, req) != 0){
		printf("Unable to read signature\n");
		return 1;
	}

	if(parse_pubkey(return_value, req) != 0){
		printf("Unable to read evp pkey\n");
		return 1;
	}

	if(parse_subject(return_value, req) != 0){
		printf("Unable to read subject\n");
		return 1;
	}

	if(parse_extension(return_value, req) != 0){
		printf("Unable to read extension");
		return 1;
	}

	X509_REQ_free(req);
	BIO_free(bio);
}
