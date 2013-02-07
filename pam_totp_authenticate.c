// pam_totp - GPLv2, Sascha Thomas Spreitzer, https://fedorahosted.org/pam_totp

#include "pam_totp.h"

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{ // by now, a dummy
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
{
	debug(pamh, "Starting");
	pam_totp_opts opts;

	if( PAM_SUCCESS != parse_opts(pamh, &opts, argc, argv) )
	{
		debug(pamh, "Could not parse module options.");
		cleanup(&opts);
		return PAM_AUTH_ERR;
	}
	if ( PAM_SUCCESS != pam_get_item(pamh, PAM_USER, &opts.user) )
	{
		debug(pamh, "Could not get user item from pam.");
		cleanup(&opts);
		return PAM_AUTH_ERR;
	}
	debug(pamh,"Verified user");
	int ret;
	ret = verify_user(pamh, opts);
	if( PAM_SUCCESS != ret)
	{
		if ( ret == CURLE_COULDNT_CONNECT ){
			debug(pamh, "Unable to connect to server!");
			cleanup(&opts);
			return PAM_AUTH_ERR;
		}
		if (PAM_SUCCESS != should_provision(pamh)){
			cleanup(&opts);
			return PAM_SUCCESS;
		}
		if( PAM_SUCCESS != provision_user(pamh, &opts)){
			debug(pamh, "There was an error provisioning the user");
			cleanup(&opts);
			return PAM_AUTH_ERR;
		}
		if( PAM_SUCCESS != provision_secret(pamh, opts)){
			debug(pamh, "There was an error provisioning the secret");
			cleanup(&opts);
			return PAM_AUTH_ERR;
		}
		if( PAM_SUCCESS != provision_scratch(pamh, opts)){
                        debug(pamh, "There was an error provisioning the scratch tokens");
			cleanup(&opts);
                        return PAM_AUTH_ERR;
                }
		cleanup(&opts);
		return PAM_AUTH_ERR;
	}
	opts.token = NULL;
	if(opts.use_authtok){
		if( PAM_SUCCESS != pam_get_item(pamh, PAM_AUTHTOK, &opts.token) )
		{
			debug(pamh, "Could not get password item from pam.");
		}
	}

	if(NULL == opts.token){
		if( PAM_SUCCESS != get_password(pamh, &opts) )
		{
			debug(pamh, "Could not get password from user. No TTY?");
			cleanup(&opts);
			return PAM_AUTH_ERR;
		} else {
			pam_set_item(pamh, PAM_AUTHTOK, opts.token);
		}
	}

	if( PAM_SUCCESS != verify_token(pamh, opts) )
	{
		debug(pamh, "There was an error verifying user token.");
		cleanup(&opts);
		return PAM_AUTH_ERR;
	}
	cleanup(&opts);
	return PAM_SUCCESS;
}

