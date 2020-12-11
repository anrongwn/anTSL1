#pragma once
#include <stdio.h>
#include <string.h>
#include "openssl/err.h"
#include "openssl/ssl.h"
#include "openssl/conf.h"
#include "openssl/engine.h"
#include <assert.h>

//an ca cert
static const char * an_ca = R"(-----BEGIN CERTIFICATE-----
MIIFIjCCAwoCCQD00uDwsE8jgzANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJj
bjESMBAGA1UECAwJR3VhbmdEb25nMRIwEAYDVQQHDAlHdWFuZ1pob3UxCzAJBgNV
BAoMAmFuMQ8wDQYDVQQDDAZhbl9kZXYwHhcNMjAwOTE0MTA0MDM4WhcNMzAwOTEy
MTA0MDM4WjBTMQswCQYDVQQGEwJjbjESMBAGA1UECAwJR3VhbmdEb25nMRIwEAYD
VQQHDAlHdWFuZ1pob3UxCzAJBgNVBAoMAmFuMQ8wDQYDVQQDDAZhbl9kZXYwggIi
MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDFu2dsqaiyaA00U65JGY6UH47J
zEw8bOtp1KXRTCBq+Xyeyv5Kcw2+o6GgL5aroVBU5DZY+AqKHOkPSXLO4c3XX9vK
a5NRzMQIUVj2rWHDxny8oEwlk819v/geoHq9O6PV7T6zuGqQEvZboBtA6TZocYuH
C3S/H4wvCMnAmXvXoK2kpMJTW/qxrn65yDmOR7SYle1wWyT4SnUKkpOLcs/Q80gZ
PSCD8XQqeo7TGpFCSa5fR72KCAPDxPOV5OAYEgshkBQ3frzsQ/ECEYpX2nPv18kM
S3BSIZS0j+HeNz7ilISVYAcszJMzLuvLcRM+87sat8jejs5/R4f45OzXC6XW8YQy
7GCXBpPhVt6nV/B5zZc5qM/gqiFmZwbqlTYqGj4qlvo2DO9xSjT/WuQxDaHlIwRx
/Tk5FsTKYZ27FpskRjC02m0i7H3d2zTFXCS56WHl40pxvoRm8EaKO/17SU9/wNWC
Jx4f8TXCr42rX7OyfHKWhvcsGWtX+cqFhgIwt1Xsy8/YnjgwMX4MMysVFti2g+8y
BQtTm6Z6B5FQyO+PidCqbCRn2RAVxWQG9gGqfcXPjpfp2oFTwy3qDFGFFg7UDHNA
+0NFgSzFYPb/AY1uPRO/PvQHYtTo5je4TgLTji896J9O3KACok957f7V+pwgQQv0
zusFivm5N+mHrR33tQIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQBE3JIHJnabDCU1
sfd6zd9S3D0KdptylGH0SpMrGE03k/75rUZf2EMiGvhxfrG6nxjYX2/gMQTwSk5R
d0GfMLGbFiHYfFswYwV2g4fk8OqYcLretRdBSfgL6ndFkMIPPhmZVo6q4rD+rujM
PzEMsSOBUnrsiaMpxLjfnv3j9JikQLh5xdWErbcAD0wOg4jNgXIHmFXTL5m8owQo
0xpHU692xh2SYKE3ZBRPtg82IPGSQ/tzf4DLkCQp35d0zerRqobbUfCfeQbG72ns
yODHoX+qsaYWj4/8B7T2ktdL/oi+nm5HgNyGl9bSf2gwAVJR4QRryLcBovc9Chkb
QQJ3F2ricoMUz/irRM0ohzgZ2a5TYNZ7syodlc7lfrX+fApu9mo642iSmMj4j794
U1kK1br0kSUq5tmzwdXQUfAPLE1njctaDsJpyOOeVzjpcXiOcSKXLdvFydMwGSMk
G0u1LWj5hAviVqz/UjaJjyZANm0VbKo9pnvONUT4f4xIsN5CGI5MOm7z0SEwejvK
2jwhFxGJyG3+gv8nyJtlmstGKs/okDt0k7+qmYYOqkQ5JOqGtQFm/Dv40knp945X
28IlQzN009Y/g2EPSeSlU7LmcIOPgV6IfeFyv8gog4NHFRVoPP2ws2UOVJaN/mOn
H3aDhjRRpSPmo1r5MeuQ+4bCH3RpHw==
-----END CERTIFICATE-----
)";

//an server cert
static const char * an_server = R"(-----BEGIN CERTIFICATE-----
MIIEVjCCAj6gAwIBAgIJAMyvLVhUwp7LMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNV
BAYTAmNuMRIwEAYDVQQIDAlHdWFuZ0RvbmcxEjAQBgNVBAcMCUd1YW5nWmhvdTEL
MAkGA1UECgwCYW4xDzANBgNVBAMMBmFuX2RldjAeFw0yMDA5MTQxMDQ1MzdaFw0z
MDA5MTIxMDQ1MzdaMFMxCzAJBgNVBAYTAmNuMRIwEAYDVQQIDAlHdWFuZ0Rvbmcx
EjAQBgNVBAcMCUd1YW5nWmhvdTELMAkGA1UECgwCYW4xDzANBgNVBAMMBmFuX2Rl
djCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKbTI/CvMnkK7VFuYDGs
WA8t+akPz33gn+HPtiIOzunm2r0qrDylMjNGGD9VFgvLSKlYbEiyJQ6ghTF38y2A
6pYo39jWqrmBkzxwxYxUQUNCdcs8eDckmeHKme+kcVDJaZqPVUlmG+NMTSLBLcRG
H87bfGd1U+ZgGHTbxd2TlyqsEQ7pVIRA+9symG8ypnAd0d0xL9LBNy2KirdjJ4B/
McZu4MZHZOEkTOESijGKVGsHx3FbmOnqTLNqjcTvFJsn48lkO8GJjitQZD9s5kAL
MQHuPZkyfMtT24sgReoApptNc+C4WBe/5phOd5S+vllYQCQViYVrhzYn3dK60fqJ
BhsCAwEAAaMtMCswKQYDVR0RBCIwIIIPMTE0LjExNC4xMTQuMTE0ggc4LjguOC44
hwTAqIA7MA0GCSqGSIb3DQEBCwUAA4ICAQCgqEqp6vZKdtJ/VVa8YFFzXnTJtb6M
XJSYCsWnckOXuv4bvaXUrAFGsRc0t2YwExiJ6zUrLLMGyKYx6hGhrrJTRTwVIctb
1LEKMYQKGVn4rawwvr8Y4n9B9Ev+1NFffYcgzKASaZStBHxCrbycYN/mGMhvigGy
N80Lv0IahPDo2iywm5d24VypUki9W9ii+d2zHtnfaKQCBpuraAoEBPAkADGu4nHC
7uSf+5CDu6/NbZtD4/ogJGXg6UweKlWe9lbZu5cCMBE0YL69CH0cluwppvWIa8SK
/TVnSGrSqo6wRngOCTWPmv0NiOdbag4ARolhXZWi35K9WNgdT4Rkjgwm21tuuEG8
bbmHHkpvq6jMfhaItSUAq8gr+36YI+glSvEP/Xz+wzunsENraTiJxZm24hLO5rCu
++Zl0r/t+xNCSi/Jkgu6xFcmMfAMY2BvTQooIdP7ME288WGXxJ8H4gJ1JiESWZNi
xC3WkdkjCS5RqcTLVcWu1BVy3UROe62gLCMCgPGvTEtYDBFUGQVM9zMyDnKxy0tL
U4RlXoP7rcGTYlYi8VfHFh05pM2uKDMtiwsv6WZAUrSlkYFR0Icjz9rWklNNvmPP
5K+p3MOrsJVKmxuoBEK9wAIf7zXZncAKXN6EJW/2xA0PoHClQ3xVCPHRhM0jTZOs
prUFvTvzPpcPZw==
-----END CERTIFICATE-----
)";

//an server private key
static const char * an_server_privatekey = R"(-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAptMj8K8yeQrtUW5gMaxYDy35qQ/PfeCf4c+2Ig7O6ebavSqs
PKUyM0YYP1UWC8tIqVhsSLIlDqCFMXfzLYDqlijf2NaquYGTPHDFjFRBQ0J1yzx4
NySZ4cqZ76RxUMlpmo9VSWYb40xNIsEtxEYfztt8Z3VT5mAYdNvF3ZOXKqwRDulU
hED72zKYbzKmcB3R3TEv0sE3LYqKt2MngH8xxm7gxkdk4SRM4RKKMYpUawfHcVuY
6epMs2qNxO8UmyfjyWQ7wYmOK1BkP2zmQAsxAe49mTJ8y1PbiyBF6gCmm01z4LhY
F7/mmE53lL6+WVhAJBWJhWuHNifd0rrR+okGGwIDAQABAoIBACKAdGRot3WVLvOy
ci6TyDqLdaDjZjRQaoCXJsHwchap6f9Jfgmk2LcF/inK/R4/Uq3DXdHDFirqQ+Gx
PxfgG6Qmm/UKoJBxHfRYFmMpYb35VsdLoEk3RqQN9Lw9NDpTDYYrsqXVelsOAr33
WfHH1vg/KIF1IH76zNQOR+PFjHQEgHEqAVU2VCj+BPWdXai4uevl5w+N+/AMVaOm
WaGW1MMBGfrQ6TGJc8gOZ4Pf7CI6ptPC6357KgFnI7wgsGvG3dulOBjTFLAW0THe
g3As2/3OZRybgm0+Dh3PJPcUtvu1BHYtyYEDQ8nahIHpX0owxoDGE0broPFxYDpo
uecN1MECgYEA3JEWfrwwW5gAQsNS0cckBlGbI43slDHu3iDdqxVR07p2x4H7tw1o
EhIpMMK7a0TblO1VcZN2xE6moHZC1a5R8thKHItdbOnAEsfa/dJ6isK56NzK8WZZ
22dnHTq7OaUvKnOWuAcuPI0gkuMk8RaATjOliBxJZK4Qg1LDtXoZg8sCgYEAwZ/j
VVL4KOgn6OME+iGLtQUJF4k4mTLUavkwgZhPNP0Wo9OPCAZhDd2QjH/HnrrW62pq
4BsOjS4oufwzzy2rtz/+SWe/nK6hBzoAo5bY6NTSvcTRB7J7PYa1EIrTFHwbCPW4
bahycnStt25wfcDb76S50QpDfh2FvN6caHiVXPECgYEAhvwUNEOfpK6FmlZHXTLu
jR9sPnohCyDz+uVKQ+WsSlOXVcnq7sA5rLWIl9rVMHTXnXESFYwV51XrC9DUXkls
xZ4w3P89keYMMnI1R5mEfV9mv2hAmzP0Uh4aMP08j67UCrrqxn0+grgr8zkn5pPK
uhFJgN8u23rbiEMimvG6o7kCgYEAgFNijMs3c40h3kSPqOOQv0F+HB4y5737cIaE
8m8ql7jhR2TQWAY6TsE4qxWJDJdSF6Zo/OyRwVoFXfZbtATV2NbNxoK/SK2oRazY
fZNdYTqkDWejDhHpggaEfFk1uk7icBbCy9KnP1o7Q+YrIf0vBu3KxVOjFbOlTl7P
lKHOhFECgYEAt60znlZbciBjFCXkTmz/isSVU26kx12tSHD3MgBPDpGJuNUMc0dU
vyW+JjlCRZgBW43l88Z8qfSG+rOw6Go9RTuHJY6CCdyc2eaeow1ijxrj5eTrELwe
Jh8tGb3ezKu97hSMD2sXIupBBYqZOwmSmtJmjasmxbGnFTg75LoJxFM=
-----END RSA PRIVATE KEY-----)";


//
static inline 
int an_load_verify_locations(SSL_CTX *ctx) {
	assert(ctx);
	if (nullptr == ctx) return -1;

	BIO * bi = BIO_new_mem_buf((void*)an_ca, strlen(an_ca));
	if (nullptr == bi) return -1;

	//X509 *certX = d2i_X509_bio(bi, nullptr); //der¸ñÊ½ //pem×ªdev: openssl x509 -in cert.pem -inform PEM -out cert.der -outform DER
	X509 *certX = PEM_read_bio_X509(bi, nullptr, 0, nullptr);
	//X509_STORE *certS = SSL_CTX_get_cert_store(ctx);

	int rc = X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), certX);

	X509_free(certX);
	BIO_free(bi);

	return rc;
}

static inline
int an_load_use_certificate(SSL_CTX *ctx) {
	assert(ctx);
	if (nullptr == ctx) return -1;

	BIO * bi = BIO_new_mem_buf((void*)an_server, strlen(an_server));
	if (nullptr == bi) return -1;

	X509* xCert = PEM_read_bio_X509(bi, nullptr, 0, nullptr);
	int rc  = SSL_CTX_use_certificate(ctx, xCert);

	X509_free(xCert);
	BIO_free(bi);

	return rc;
}


static inline 
int an_load_use_PrivateKey(SSL_CTX *ctx) {
	assert(ctx);
	if (nullptr == ctx) return -1;

	BIO * bi = BIO_new_mem_buf((void*)an_server_privatekey, strlen(an_server_privatekey));
	if (nullptr == bi) return -1;

	RSA *rsa = PEM_read_bio_RSAPrivateKey(bi, nullptr, 0, nullptr);
	int rc  = SSL_CTX_use_RSAPrivateKey(ctx, rsa);

	RSA_free(rsa);
	BIO_free(bi);
	return rc;
}