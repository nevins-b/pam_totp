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
void display_message(pam_handle_t* pamh, const char *msg)
{
	pam_info(pamh, "%s", msg);
}
int should_provision(pam_handle_t* pamh)
{
	char* res = NULL;
	
	pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &res, "Would you like to provision a secret now? [Y/n]: ");
	if (NULL != res)
	{
		if(strlen(res) == 0)
			free(res);
			return PAM_SUCCESS;
		if( strlen(res) > 0 && ((strncmp(res,"y", 1)) == 0 || (strncmp(res,"Y", 1)) == 0))
			free(res);
			return PAM_SUCCESS;
	}
	free(res);
	return PAM_AUTH_ERR;
}
int get_password(pam_handle_t* pamh, pam_totp_opts* opts)
{
	char* p = NULL;
	const char *prompt;

	if(config_lookup_string(&config, "pam_totp.settings.prompt", &prompt) == CONFIG_FALSE)
		prompt = DEF_PROMPT;

	pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &p, "%s", prompt);

	if( NULL != p && strlen(p) > 0)
	{
		opts->token = p;
		free(p);
		return PAM_SUCCESS;
	}
	free(p);
	return PAM_AUTH_ERR;
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
		int next_arg;
		for(next_arg = 0; next_arg < argc; next_arg++)
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
	
	if(config_lookup_string(&config, "pam_totp.settings.provisionpath", &opts->provision_path) == CONFIG_FALSE)
		opts->provision_path = DEF_PROVISIONPATH;
		
	if(config_lookup_string(&config, "pam_totp.settings.userfield", &opts->user_field) == CONFIG_FALSE)
		opts->user_field = DEF_USER;

	if(config_lookup_string(&config, "pam_totp.settings.tokenfield", &opts->token_field) == CONFIG_FALSE)
		opts->token_field = DEF_TOKEN;

	if(config_lookup_string(&config, "pam_totp.settings.authdomain", &opts->auth_domain) == CONFIG_FALSE)
                opts->auth_domain = DEF_AUTHDOMAIN;

	if(config_lookup_string(&config, "pam_totp.settings.hostname", &opts->hostname) == CONFIG_FALSE)
		get_hostname(opts);

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
	//config_destroy(&config);
	return PAM_SUCCESS;
}

void get_hostname(pam_totp_opts *opts)
{
	char hostname[256];
	hostname[255] = '\0';
	gethostname(hostname, 255);
	opts->hostname = hostname;
}

int verify_user(pam_handle_t *pamh, pam_totp_opts opts)
{
	debug(pamh,"Verifying User...");
	char* url = NULL;
	post_arg head, host;
	int ret = 0;
	head.key = opts.user_field;
	head.value = opts.user;
	head.next = &host;
	host.key = "hostname";
	host.value = opts.hostname;
	host.next = NULL;	
	ret = asprintf(&url,"%s%suser/", opts.url, opts.verify_path);
	debug(pamh, url);
	if( ret == -1 )
        {
                free(url);
                return PAM_AUTH_ERR;
        }
	debug(pamh,"Fetching verify URL...");
	ret = fetch_url(pamh, opts, url, &head);
	debug(pamh, "Fetch complete!");
	free(url);
	free(recvbuf);
	recvbuf = NULL;
	recvbuf_size=0;
	if(ret == CURLE_OK || ret == PAM_SUCCESS)
		return PAM_SUCCESS;
	return ret;
}

int verify_token(pam_handle_t *pamh, pam_totp_opts opts)
{
	char* url = NULL;
	post_arg head, token, host;
	int ret = 0;
	head.key = opts.user_field;
	head.value = opts.user;
	head.next = &token;
	token.key = opts.token_field;
	token.value = opts.token;
	token.next = &host;
	host.key = "hostname";
	host.value = opts.hostname;
	host.next = NULL;	
	ret = asprintf(&url, "%s%stoken/", opts.url, opts.verify_path);
	if( ret == -1 )
	{
		free(url);
		return PAM_AUTH_ERR;
	}
	ret = fetch_url(pamh, opts,  url, &head);
	free(url);
	free(recvbuf);
	recvbuf = NULL;
        recvbuf_size=0;
	if(ret == CURLE_OK || ret == PAM_SUCCESS){
		debug(pamh, "Returning OK");
		return PAM_SUCCESS;
	}
	char *res;
	asprintf(&res, "%d", ret);
	debug(pamh, "Returning");
	debug(pamh, res);
	free(res);
	return ret;
}

int provision_user(pam_handle_t *pamh, pam_totp_opts *opts){
	char* url = NULL;
	post_arg head, host;
	int ret = 0;
	head.key = opts->user_field;
	head.value = opts->user;
	head.next = &host;
	host.key = "hostname";
	host.value = opts->hostname;
	host.next = NULL;	
	ret = asprintf(&url,"%s%suser/", opts->url, opts->provision_path);
	if( ret == -1 )
        {
                free(url);
                return PAM_AUTH_ERR;
        }
	ret = fetch_url(pamh, *opts, url, &head);
	free(url);
	if( NULL == recvbuf )
		return PAM_AUTH_ERR;
	if( CURLE_OK != ret)
		return PAM_AUTH_ERR;
	asprintf(&opts->provisioning_key, "%s", recvbuf );
	free(recvbuf);
	recvbuf = NULL;
        recvbuf_size=0;
	return PAM_SUCCESS;
}

int provision_secret(pam_handle_t *pamh, pam_totp_opts opts)
{
	char* url = NULL;
	post_arg head, host, key;
	int ret = 0;
	head.key = opts.user_field;
	head.value = opts.user;
	head.next = &key;
	key.key = "key";
	key.value = opts.provisioning_key;
	key.next = &host;
	host.key = "hostname";
	host.value = opts.hostname;
	host.next = NULL;	
	ret = asprintf(&url,"%s%ssecret/", opts.url, opts.provision_path);
	if( ret == -1 )
        {
                free(url);
                return PAM_AUTH_ERR;
        }
	ret = fetch_url(pamh, opts, url, &head);
	free(url);
	if( NULL == recvbuf )
		return PAM_AUTH_ERR;
	if( CURLE_OK != ret)
		return PAM_AUTH_ERR;
	char *msg = NULL;
	ret = asprintf(&msg, "Your Secret is:\n%s\n", recvbuf);
	display_message(pamh, msg);
	free(recvbuf);
	recvbuf = NULL;
        recvbuf_size=0;
	return PAM_SUCCESS;
}
int provision_scratch(pam_handle_t *pamh, pam_totp_opts opts)
{
        char* url = NULL;
        post_arg head, host, key;
        int ret = 0;
        head.key = opts.user_field;
        head.value = opts.user;
        head.next = &key;
        key.key = "key";
        key.value = opts.provisioning_key;
        key.next = &host;
        host.key = "hostname";
        host.value = opts.hostname;
        host.next = NULL;
        ret = asprintf(&url,"%s%sscratch/", opts.url, opts.provision_path);
        if( ret == -1 )
        {
                free(url);
                return PAM_AUTH_ERR;
        }
        ret = fetch_url(pamh, opts, url, &head);
        free(url);
        if( NULL == recvbuf )
                return PAM_AUTH_ERR;
        if( CURLE_OK != ret)
                return PAM_AUTH_ERR;
        char *msg = NULL;
        ret = asprintf(&msg, "Your Scratch Tokens are:\n%s\nNow closing connection", recvbuf);
        display_message(pamh, msg);
        free(recvbuf);
        recvbuf = NULL;
        recvbuf_size=0;
        return PAM_SUCCESS;
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
char *sanitize_url(pam_handle_t *pamh, CURL* session, char* url){
	char *pch, *safe_url, *tmp;
	pch = strtok (url,":");
	if(pch == NULL || strlen(pch) > 5){
		free(pch);
		return NULL;
	}
	if(strlen(pch) == 4 && 0 != (strncmp(pch,"http",4))){
		free(pch);
		return NULL;
	}
	if(strlen(pch) == 5 && 0 != (strncmp(pch,"https",5))){
                free(pch);
                return NULL;
        }
	asprintf(&safe_url, "%s:/", pch);
	int first = 1;
	while (1){
		pch = strtok (NULL, "/");
		if (pch == NULL){
			debug(pamh, "Ending Sanitize");
			break;
		}
		if(first){
			asprintf(&tmp, "%s/%s", safe_url, pch);
			first = 0;
			free(safe_url);
		} else {
			char *safe = curl_easy_escape(session, pch, 0);
			asprintf(&tmp, "%s/%s", safe_url, safe);	
			curl_free(safe);
		}
		safe_url = NULL;
		asprintf(&safe_url, "%s", tmp);	
		tmp = NULL;
	}
	asprintf(&tmp, "%s/", safe_url);
	safe_url = NULL;
	asprintf(&safe_url, "%s", tmp);
	free(tmp);
	return safe_url;
}
char *build_post(pam_handle_t *pamh, CURL* session, post_arg* head ){
	post_arg* curr;
	post_arg *next;
	int first = 1;
	int ret;
	char* res;
	char* tmp;
	for(curr = head; NULL != curr; curr = next){
		char *safe = curl_easy_escape(session, curr->value, 0);
		if(first){
			ret = asprintf(&res, "%s=%s", curr->key, safe);
		} else {
                	ret = asprintf(&tmp, "%s&%s=%s", res, curr->key, safe);
		}
		curl_free(safe);
		if(!first){
			res = NULL;
			asprintf(&res, "%s", tmp );
			tmp= NULL;
		} else {
			first = 0;
		}
		if(ret == -1 || res == NULL){
			free(res);
			return NULL;
		}
		next = curr->next;
	}
	free(tmp);
	return res;
}

int curl_debug(CURL *C, curl_infotype info, char * text, size_t textsize, void* pamh)
{
	debug((pam_handle_t*)pamh, text);
	return 0;
}

void curl_error(pam_handle_t *pamh, CURL *session)
{
}

int fetch_url(pam_handle_t *pamh, pam_totp_opts opts, char *url, post_arg* post_head)
{
	debug(pamh,"Setting up curl...");
	CURL* session = NULL;
	if( 0 != curl_global_init(CURL_GLOBAL_ALL) )
	{
		goto curl_error;
	}
	if( NULL == (session = curl_easy_init() ) )
	{
		goto curl_error;
	}
	if( 1 == pam_totp_debug)
	{
		debug(pamh,"Setting Curl Debug");
		if( CURLE_OK != curl_easy_setopt(session, CURLOPT_VERBOSE, 1) )
		{
			goto curl_error;
		}
		if( CURLE_OK != curl_easy_setopt(session, CURLOPT_DEBUGDATA, pamh) )
		{
			goto curl_error;
		}
		if( CURLE_OK != curl_easy_setopt(session, CURLOPT_DEBUGFUNCTION, curl_debug) )
		{
			goto curl_error;
		}
		debug(pamh,"Debug Set");
	}
	char* post_data = build_post(pamh, session, post_head);
	if( CURLE_OK != curl_easy_setopt(session, CURLOPT_POSTFIELDS, post_data) )
	{
		debug(pamh,"something strange happened..");
		goto curl_error;
	}
	debug(pamh,"Setting User Agent");
	if( CURLE_OK != curl_easy_setopt(session, CURLOPT_USERAGENT, USER_AGENT) )
	{
		goto curl_error;
	}
	debug(pamh,"Setting write function");
	if( CURLE_OK != curl_easy_setopt(session, CURLOPT_WRITEFUNCTION, curl_wf) )
	{
		goto curl_error;
	}
	debug(pamh, "Sanitizing URL");	
	char* safe_url = sanitize_url(pamh, session, url);
	debug(pamh,"Setting URL");
	if( CURLE_OK != curl_easy_setopt(session, CURLOPT_URL, safe_url) )
	{
		goto curl_error;
	}
	debug(pamh,"Setting SSL options");
	if( CURLE_OK != curl_easy_setopt(session, CURLOPT_SSLCERT, opts.ssl_cert) )
	{
		goto curl_error;
	}
	if( CURLE_OK != curl_easy_setopt(session, CURLOPT_SSLCERTTYPE, "PEM") )
	{
		goto curl_error;
	}
	if( CURLE_OK != curl_easy_setopt(session, CURLOPT_SSLKEY, opts.ssl_key) )
	{
		goto curl_error;
	}
	if( CURLE_OK != curl_easy_setopt(session, CURLOPT_SSLKEYTYPE, "PEM") )
	{
		goto curl_error;
	}
	if( CURLE_OK != curl_easy_setopt(session, CURLOPT_CAINFO, opts.ca_cert) )
	{
		goto curl_error;
	}
	if( opts.ssl_verify_host == true )
	{
		if( CURLE_OK != curl_easy_setopt(session, CURLOPT_SSL_VERIFYHOST, 2) )
		{
			goto curl_error;
		}
	}
	else
	{
		if( CURLE_OK != curl_easy_setopt(session, CURLOPT_SSL_VERIFYHOST, 0) )
		{
			goto curl_error;
		}
	}
	if( opts.ssl_verify_peer == true )
	{
		if( CURLE_OK != curl_easy_setopt(session, CURLOPT_SSL_VERIFYPEER, 1) )
		{
			goto curl_error;
		}
	}
	else
	{
		if( CURLE_OK != curl_easy_setopt(session, CURLOPT_SSL_VERIFYPEER, 0) )
		{
			goto curl_error;
		}
	}


	debug(pamh,"Performing curl");
	int ret;	
	ret = curl_easy_perform(session);
	if( ret != CURLE_OK )
	{
		if (session != NULL)
                	curl_easy_cleanup(session);
		if (post_data != NULL)
                	free(post_data);
        	if (safe_url != NULL)
                	free(safe_url);
		return ret;
	}
	if (PAM_SUCCESS != check_status_code(pamh, session))
	{
		goto curl_error;
	}
	debug(pamh, "No Errors with Curl!");
	curl_easy_cleanup(session);
	return ret;
curl_error:
	debug(pamh, "There was an error with curl!");
	if (session != NULL)
		curl_easy_cleanup(session);
	if (post_data != NULL)
		free(post_data);
	if (safe_url != NULL)
		free(safe_url);
	return PAM_AUTH_ERR;

}

int check_status_code(pam_handle_t *pamh, CURL *session)
{
	long http_code = 0;
	curl_easy_getinfo (session, CURLINFO_RESPONSE_CODE, &http_code);
	if (http_code == 200)
	{
		debug(pamh,"http_code was good!");
		return PAM_SUCCESS;
	}
	else
	{
		debug(pamh, "http_code was bad!");
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

