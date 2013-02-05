// pam_totp - GPLv2, Sascha Thomas Spreitzer, https://fedorahosted.org/pam_totp

#include "pam_totp.h"
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

char* recvbuf = NULL;
size_t recvbuf_size = 0;
static config_t config;

void debug(pam_handle_t* pamh, const char *msg)
{
	pam_syslog(pamh, LOG_ERR, "%s", msg);
}

int get_password(pam_handle_t* pamh, pam_totp_opts* opts)
{
	char* p = NULL;
	const char *prompt;
	int prompt_len = 0;

	if(config_lookup_string(&config, "pam_totp.settings.prompt", &prompt) == CONFIG_FALSE)
		prompt = DEF_PROMPT;
	
	pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &p, "%s", prompt);
	
	if( NULL != p && strlen(p) > 0)
	{
		opts->token = p;
		return PAM_SUCCESS;
	}
	else
	{
		return PAM_AUTH_ERR;
	}
}


int parse_opts(pam_handle_t *pamh, pam_totp_opts *opts, int argc, const char *argv[])
{
#if defined(DEBUG)
	pam_totp_debug = true;
#else
	pam_totp_debug = false;
#endif
	opts->configfile = NULL;
	opts->use_authtok = false;	
	if(argc > 0 && argv != NULL)
	{	
		for(int next_arg = 0; next_arg < argc; next_arg++)
		{
			if( strcmp( argv[next_arg], "debug") == 0)
			{
				pam_totp_debug = true;
				continue;
			}
			
			if( strncmp( argv[next_arg], "config=", 7) == 0)
			{
				// Skip the first 7 chars ('config=').
				opts->configfile = strdup(argv[next_arg] + 7);
				continue;
			}
	
			if( strcmp( argv[next_arg], "use_authtok") == 0)
			{
				opts->use_authtok = true;
				continue;
			}
		}
	}
	if(opts->configfile == NULL)
		opts->configfile = strdup("/etc/pam_totp.conf");
	
	config_init(&config);
	config_read_file(&config, opts->configfile);
	// General Settings
	if(config_lookup_string(&config, "pam_totp.settings.url", &opts->url) == CONFIG_FALSE)
		opts->url = DEF_URL;
		
	if(config_lookup_string(&config, "pam_totp.settings.verifypath", &opts->verify_path) == CONFIG_FALSE)
		opts->verify_path = DEF_VERIFYPATH;
		
	if(config_lookup_string(&config, "pam_totp.settings.userfield", &opts->user_field) == CONFIG_FALSE)
		opts->user_field = DEF_USER;
	
	if(config_lookup_string(&config, "pam_totp.settings.tokenfield", &opts->token_field) == CONFIG_FALSE)
		opts->token_field = DEF_TOKEN;
	
	if(config_lookup_string(&config, "pam_totp.settings.hostname", &opts->hostname) == CONFIG_FALSE)
		opts->hostname = DEF_HOSTNAME;	
	// SSL Options
	if(config_lookup_string(&config, "pam_totp.ssl.client_cert", &opts->ssl_cert) == CONFIG_FALSE)
		opts->ssl_cert = DEF_SSLCERT;
	
	if(config_lookup_string(&config, "pam_totp.ssl.client_key", &opts->ssl_key) == CONFIG_FALSE)
		opts->ssl_key = DEF_SSLKEY;
	if(config_lookup_string(&config, "pam_totp.ssl.ca_cert", &opts->ca_cert) == CONFIG_FALSE)
		opts->ca_cert = DEF_CA_CERT;
	
	if(config_lookup_bool(&config, "pam_totp.ssl.verify_host", (int *)&opts->ssl_verify_host) == CONFIG_FALSE)
		opts->ssl_verify_host = true;
	
	if(config_lookup_bool(&config, "pam_totp.ssl.verify_peer", (int *)&opts->ssl_verify_peer) == CONFIG_FALSE)
		opts->ssl_verify_peer = true;

	return PAM_SUCCESS;
}

void get_hostname(pam_totp_opts *opts)
{
	char hostname[256];
	hostname[255] = '\0';
	gethostname(hostname, 255);
	opts->hostname = hostname;
}

size_t curl_wf(void *ptr, size_t size, size_t nmemb, void *stream)
{
	size_t oldsize=0;

	if( 0 == size * nmemb )
		return 0;

	if( NULL == recvbuf )
	{
		if( NULL == ( recvbuf = calloc(nmemb, size) ) )
		{
			return 0;
		}
	}

	// Check the multiplication for an overflow
	if (((nmemb * size) > (SIZE_MAX / nmemb)) ||
			// Check the addition for an overflow
			((SIZE_MAX - recvbuf_size) < (nmemb * size))) {
		// The arithmetic will cause an integer overflow
		return 0;
	}
	if( NULL == ( recvbuf = realloc(recvbuf, recvbuf_size + (nmemb * size)) ) )
	{
		return 0;
	}
	else
	{
		oldsize = recvbuf_size;
		recvbuf_size += nmemb * size;
		memcpy(recvbuf + oldsize, ptr, size * nmemb);
		return(size*nmemb);
	}
}

int curl_debug(CURL *C, curl_infotype info, char * text, size_t textsize, void* pamh)
{
	debug((pam_handle_t*)pamh, text);
	return 0;
}

void curl_error(CURL *session, char *post)
{
	
	if (session != NULL)
		curl_easy_cleanup(session);
	if (post != NULL)
		free(post);
}

int verify_user(pam_handle_t *pamh, pam_totp_opts *opts)
{
	CURL* session = NULL;
	char* post = NULL;
	char* url = NULL;
	int ret = 0;
	if( NULL == opts->user )
		opts->user = "";
		
	if( NULL == opts->hostname )
		opts->hostname = "";
		
	if( 0 != curl_global_init(CURL_GLOBAL_ALL) )
	{
		curl_error(&session,post);
		return PAM_AUTH_ERR;
	}
	if( NULL == (session = curl_easy_init() ) )
	{
		curl_error(&session,post);
		return PAM_AUTH_ERR;
	}
	
	char *safe_user = curl_easy_escape(session, opts->user, 0);
	if( safe_user == NULL )
	{
		curl_error(&session,post);
		return PAM_AUTH_ERR;
	}
	
	char *safe_hostname = curl_easy_escape(session, opts->hostname, 0);
	if( safe_hostname == NULL )
	{
		curl_error(&session,post);
		return PAM_AUTH_ERR;
	}
	
	ret = asprintf(&post, "%s=%s&hostname=%s", opts->user_field,
							safe_user,
							safe_hostname);
	
	curl_free(safe_user);
	curl_free(safe_hostname);
	if (ret == -1)
	{
		curl_error(&session,post);
		return PAM_AUTH_ERR;
	}
	ret = asprintf(&url, "%s%suser", opts->url, opts->verify_path);
	if (ret == -1)
	{
		curl_error(&session,url);
		return PAM_AUTH_ERR;
	}
	fetch_url(pamh, *opts, &session, url, post);
	free(post);
	if (NULL != session ){
		ret = check_status_code(&session);
		curl_easy_cleanup(session);
		return ret;
	}
	return PAM_AUTH_ERR;
}
int verify_token(pam_handle_t *pamh, pam_totp_opts *opts)
{
	CURL* session = NULL;
	char* post = NULL;
	char* url = NULL;
	int ret = 0;
	if( NULL == opts->user )
		opts->user = "";
		
	if( NULL == opts->token )
		opts->token = "";
		
	if( NULL == opts->hostname )
		opts->hostname = "";
		
	if( 0 != curl_global_init(CURL_GLOBAL_ALL) )
	{
		curl_error(&session,post);
		return PAM_AUTH_ERR;
	}
	if( NULL == (session = curl_easy_init() ) )
	{
		curl_error(&session,post);
		return PAM_AUTH_ERR;
	}
	char *safe_user = curl_easy_escape(session, opts->user, 0);
	if( safe_user == NULL ){
		curl_error(&session,post);
		return PAM_AUTH_ERR;
	}
	char *safe_token = curl_easy_escape(session, opts->token, 0);
	if( safe_token == NULL )
	{
		curl_error(&session,post);
		return PAM_AUTH_ERR;
	}
	
	char *safe_hostname = curl_easy_escape(session, opts->hostname, 0);
        if( safe_hostname == NULL )
	{
                curl_error(&session,post);
		return PAM_AUTH_ERR;
	}
	
	ret = asprintf(&post, "%s=%s&%s=%s&hostname=%s", opts->user_field,
							safe_user,
							opts->token_field,
							safe_token,
							safe_hostname);
	
	curl_free(safe_token);
	curl_free(safe_user);
	curl_free(safe_hostname);
	
	if (ret == -1)
	{
		curl_error(&session,post);
		return PAM_AUTH_ERR;
	}
	ret = asprintf(&url, "%s%stoken", opts->url, opts->verify_path);
	if (ret == -1)
	{
		curl_error(&session,url);
		return PAM_AUTH_ERR;
	}
	fetch_url(pamh, *opts, &session, url, post);
	free(post);
	if (NULL != session ){
		ret = check_status_code(&session);
		curl_easy_cleanup(session);
		return ret;
	}
	return PAM_AUTH_ERR;
}

void fetch_url(pam_handle_t *pamh, pam_totp_opts opts, CURL *session, char *url, char *post)
{
	debug(pamh,"Starting Fetch");
	if( 1 == pam_totp_debug)
	{
		if( CURLE_OK != curl_easy_setopt(session, CURLOPT_VERBOSE, 1) )
		{
			curl_error(&session,post);
			return;
		}
		if( CURLE_OK != curl_easy_setopt(session, CURLOPT_DEBUGDATA, pamh) )
		{
			curl_error(&session,post);
			return;
		}
		if( CURLE_OK != curl_easy_setopt(session, CURLOPT_DEBUGFUNCTION, curl_debug) )
		{
			curl_error(&session,post);
			return;
		}
	}
	if( CURLE_OK != curl_easy_setopt(session, CURLOPT_POSTFIELDS, post) )
	{
		curl_error(&session,post);
		return;
	}
	if( CURLE_OK != curl_easy_setopt(session, CURLOPT_USERAGENT, USER_AGENT) )
	{
		curl_error(&session,post);
		return;
	}
	if( CURLE_OK != curl_easy_setopt(session, CURLOPT_WRITEFUNCTION, curl_wf) )
	{
		curl_error(&session,post);
		return;
	}
	if( CURLE_OK != curl_easy_setopt(session, CURLOPT_URL, url) )
	{
		curl_error(&session,post);
		return;
	}
	if( CURLE_OK != curl_easy_setopt(session, CURLOPT_SSLCERT, opts.ssl_cert) )
	{
		curl_error(&session,post);
		return;
	}
	if( CURLE_OK != curl_easy_setopt(session, CURLOPT_SSLCERTTYPE, "PEM") )
	{
		curl_error(&session,post);
		return;
	}
	if( CURLE_OK != curl_easy_setopt(session, CURLOPT_SSLKEY, opts.ssl_key) )
	{
		curl_error(&session,post);
		return;
	}
	if( CURLE_OK != curl_easy_setopt(session, CURLOPT_SSLKEYTYPE, "PEM") )
	{
		curl_error(&session,post);
		return;
	}
	if( CURLE_OK != curl_easy_setopt(session, CURLOPT_CAINFO, opts.ca_cert) )
	{
		curl_error(&session,post);
		return;
	}
	if( opts.ssl_verify_host == true )
	{
		if( CURLE_OK != curl_easy_setopt(session, CURLOPT_SSL_VERIFYHOST, 2) )
		{
			curl_error(&session,post);
			return;
		}
	}
	else
	{
		if( CURLE_OK != curl_easy_setopt(session, CURLOPT_SSL_VERIFYHOST, 0) )
		{
			curl_error(&session,post);
			return;
		}
	}
	if( opts.ssl_verify_peer == true )
	{
		if( CURLE_OK != curl_easy_setopt(session, CURLOPT_SSL_VERIFYPEER, 1) )
		{
			curl_error(&session,post);
			return;
		}
	}
	else
	{
		if( CURLE_OK != curl_easy_setopt(session, CURLOPT_SSL_VERIFYPEER, 0) )
		{
			curl_error(&session,post);
			return;
		}
	}
	if( CURLE_OK != curl_easy_perform(session) )
	{
		curl_error(&session,post);
		return;
	}
}

int check_status_code(CURL *session)
{
	long http_code = 0;
	curl_easy_getinfo (session, CURLINFO_RESPONSE_CODE, &http_code);
	if (http_code == 200)
	{
		return PAM_SUCCESS;
	}
	else
	{
		return PAM_AUTH_ERR;
	}
}

void cleanup(pam_totp_opts* opts)
{
	if( NULL != recvbuf )
	{
		free(recvbuf);
		recvbuf = NULL;
	}
	recvbuf_size=0;
	free(opts->configfile);
	config_destroy(&config);
}

