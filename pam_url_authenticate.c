// pam_url - GPLv2, Sascha Thomas Spreitzer, https://fedorahosted.org/pam_url

#include "pam_url.h"

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{ // by now, a dummy
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
{
	pam_url_opts opts;

	if ( PAM_SUCCESS != pam_get_item(pamh, PAM_USER, &opts.user) )
	{
		debug(pamh, "Could not get user item from pam.");
		return PAM_AUTH_ERR;
	}
	if(opts.use_authtok){
		if( PAM_SUCCESS != pam_get_item(pamh, PAM_AUTHTOK, &opts.passwd) )
		{
			debug(pamh, "Could not get password item from pam.");
		}
	}	
	if( PAM_SUCCESS != parse_opts(&opts, argc, argv, PAM_SM_AUTH) )
	{
		debug(pamh, "Could not parse module options.");
		return PAM_AUTH_ERR;
	}

	if(! opts.passwd){
		if( PAM_SUCCESS != get_password(pamh, &opts) )
		{
			debug(pamh, "Could not get password from user. No TTY?");
			return PAM_AUTH_ERR;
		} else {
			pam_set_item(pamh, PAM_AUTHTOK, opts.passwd);
		}
	}

	if( PAM_SUCCESS != fetch_url(pamh, opts) )
	{
		debug(pamh, "Could not fetch URL.");
		return PAM_AUTH_ERR;
	}

	if( PAM_SUCCESS != check_rc(opts) )
	{
		debug(pamh, "Wrong Return Code.");
		return PAM_AUTH_ERR;
	}
	cleanup(&opts);

	return PAM_SUCCESS;
}
