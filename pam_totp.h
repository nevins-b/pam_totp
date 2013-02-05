// pam_totp - GPLv2, Sascha Thomas Spreitzer, https://fedorahosted.org/pam_totp

#ifndef PAM_TOTP_H_
#define PAM_TOTP_H_


#ifndef NAME
	#define NAME "pam_totp"
#endif

#ifndef VERS
	#define VERS "0.0"
#endif

#ifndef USER_AGENT
	#define USER_AGENT NAME "/" VERS
#endif

#include <security/pam_modules.h>
#include <security/pam_ext.h>

#define PAM_SM_AUTH 1
#define PAM_SM_ACCOUNT 2
#define PAM_SM_SESSION 3
#define PAM_SM_PASSWORD 4

#ifndef _SECURITY_PAM_MODULES_H
	#error PAM headers not found on this system. Giving up.
#endif

#include <curl/curl.h>
#ifndef __CURL_CURL_H
	#error libcurl headers not found on this system. Giving up.
#endif

#include <libconfig.h>
#ifndef __libconfig_h
	#error libconfig headers not found on this system. Giving up.
#endif

#define __USE_XOPEN_EXTENDED
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <syslog.h>
#include <unistd.h>

#ifndef DEF_URL
	#define DEF_URL "https://www.example.org/"
#endif

#ifndef DEF_VERIFYPATH
	#define DEF_VERIFYPATH "verify/"
#endif

#ifndef DEF_HOSTNAME
        #define DEF_HOSTNAME "example.com"
#endif

#ifndef DEF_USER
	#define DEF_USER "user"
#endif

#ifndef DEF_TOKEN
	#define DEF_TOKEN "token"
#endif


#ifndef DEF_CA_CERT
	#define DEF_CA_CERT "/etc/pki/tls/certs/ca-bundle.crt"
#endif

#ifndef DEF_SSLKEY
	#define DEF_SSLKEY "/etc/pki/pam_totp_key.pem"
#endif

#ifndef DEF_SSLCERT
    #define DEF_SSLCERT "/etc/pki/pam_totp_cert.pem"
#endif

#ifndef DEF_PROMPT
    #define DEF_PROMPT "Token: "
#endif

bool pam_totp_debug;

typedef struct pam_totp_opts_ {
	const char *url;
	const char *verify_path;
	const char *user_field;
	const char *token_field;
	const char *hostname;
	
	char *configfile;
	bool use_authtok;
	
	const char *ssl_cert;
	const char *ssl_key;
	const char *ca_cert; 
	bool ssl_verify_peer;
	bool ssl_verify_host;

	const void *user;
	const void *token;
} pam_totp_opts;

void debug(pam_handle_t* pamh, const char *msg);
int get_password(pam_handle_t* pamh, pam_totp_opts* opts);
int parse_opts(pam_handle_t *pamh, pam_totp_opts* opts, int argc, const char** argv);
void get_hostname(pam_totp_opts* opts);
void curl_error(pam_handle_t *pamh, CURL *session);
int verify_user(pam_handle_t *pamh, pam_totp_opts* opts);
int verify_token(pam_handle_t *pamh, pam_totp_opts* opts);
void fetch_url(pam_handle_t *pamh, pam_totp_opts opts, CURL* session, char* url, char* post);
int check_status_code(CURL *session);
void cleanup(pam_totp_opts* opts);

#endif /* PAM_URL_H_ */

