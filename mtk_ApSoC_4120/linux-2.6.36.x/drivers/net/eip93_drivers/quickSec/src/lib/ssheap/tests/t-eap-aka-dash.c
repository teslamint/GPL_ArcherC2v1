/*
  t-eap-aka-dash.c

  Copyright:
          Copyright (c) 2008 SFNT Finland Oy.
  All Rights Reserved.
*/

#include <stdio.h>
#include "sshincludes.h"
#include "sshgetopt.h"
#include "ssheap.h"
#include "t-eap.h"
#include "t-eap-files.h"

static char *program;

#define SSH_DEBUG_MODULE "TestEapAkaDash"

static unsigned char *user_buf;
static size_t user_len;


#ifdef SSHDIST_EAP_AKA_DASH

#ifdef SSHDIST_TESTS_INPLACE
#define DEFAULT_RADIUS_STRING "radius://foo:foobar@172.30.4.78"
#define DEFAULT_USER_STRING "akadashuser"
#else /* SSHDIST_TESTS_INPLACE */
#define DEFAULT_RADIUS_STRING "radius://foo:foobar@1.2.3.4"
#define DEFAULT_USER_STRING "akadashuser"
#endif /* SSHDIST_TESTS_INPLACE */

Boolean
t_aka_dash_verify_kdfinput(const char *network_name, size_t length)
{
  if (length == 0)
    return FALSE;
  else
    return TRUE;
}

void
t_aka_dash_config_handler(SshEap eap, void *context)
{
  SshEapAkaParamsStruct params;

  memset(&params, 0, sizeof(params));

  SSH_DEBUG(SSH_D_HIGHOK, ("Accepting AKA-DASH method"));
  ssh_eap_accept_auth(eap, SSH_EAP_TYPE_AKA_DASH, 7);

  params.transform |= SSH_EAP_TRANSFORM_PRF_HMAC_SHA256;
  /* Set the default option, i.e. Not to verify the Network Name */
  params.verify_kdfinput = FALSE;

  if (ssh_eap_configure_protocol(eap, 
			     SSH_EAP_TYPE_AKA_DASH, 
			     (void *)&params,
			     sizeof(params)) 
	  != SSH_EAP_OPSTATUS_SUCCESS)
    ssh_fatal("Cannot configure AKA-DASH parameters");
}

void
t_aka_dash_token_handler(SshEap eap, 
                         SshUInt8 type, 
		         SshBuffer buf,
		         SshEapToken token,
		         void *context)
{
  SshEapTokenType token_type;
  SshEapToken tinput;
  SshUInt8 akadash_buffer[1024];
  int akadash_len = 0;
  void *data;
  size_t data_len;
  Boolean result = FALSE;

  SSH_ASSERT(buf != NULL);

  token_type = ssh_eap_get_token_type_from_buf(buf);
  tinput = (SshEapToken)ssh_buffer_ptr(buf);

  switch (token_type)
    {
    case SSH_EAP_TOKEN_USERNAME:
      ssh_eap_init_token_username(token,
                                  user_buf,
                                  user_len);
      break;

    case SSH_EAP_TOKEN_AKA_CHALLENGE:

      akadash_len = eap_read_sim_files(SSH_EAP_TYPE_AKA_DASH, 
				   tinput->token.buffer.dptr, 
				   tinput->token.buffer.len, 
				   akadash_buffer,
				   sizeof(akadash_buffer));
      
      /* Auth failed?  Can be noted from the length. */
      if (akadash_len == 16)
        token->type            = SSH_EAP_TOKEN_AKA_SYNCH_REQ;
      else if (akadash_len > 16)
        token->type            = SSH_EAP_TOKEN_AKA_CHALLENGE; 
      else if (akadash_len < 0)
        token->type            = SSH_EAP_TOKEN_AKA_AUTH_REJECT; 
      else
        return;

      token->token.buffer.dptr = akadash_buffer;
      token->token.buffer.len  = akadash_len;
      break;

    case SSH_EAP_TOKEN_AKA_DASH_KDF_INPUT:
     
      /* Get the data to verify */
      ssh_eap_get_token_data_from_buf(buf, &data, &data_len);
      
      SSH_DEBUG(SSH_D_NICETOKNOW, ("kdfinput: %s", data));
      /* Get the verification result of the data */
      result = t_aka_dash_verify_kdfinput(data, data_len);
      /* Init the token with the result */
      ssh_eap_init_token_kdf_input(token, result);
      break;

    default:
      token_type = SSH_EAP_TOKEN_NONE;
      break;
    }

  if (token_type != SSH_EAP_TOKEN_NONE)
    ssh_eap_token(eap, type, token);
  return;
}

static void
usage(int i)
{
  fprintf((i == 0 ? stdout : stderr), "\
Usage: %s [OPTION] ...\n\
   -P PATH                path to local listener\n\
   -c                     run as a client\n\
   -s                     run as a server\n\
   -u NAME                set username to NAME\n\
   -I                     skip identification request/response phase\n\
   -d LEVEL               set debug level string to LEVEL\n\
"
#ifdef SSHDIST_RADIUS
"\
   -r                     radius URL\n\
"
#endif /* SSHDIST_RADIUS */
         , program);
  exit(i);
}

int
main(int argc, char** argv)
{
  SshEapTestParamsStruct params;
  char opt;

  program = strrchr(argv[0], '/');
  if (program)
    program++;
  else
    program = argv[0];

  memset(&params, 0, sizeof(params));

  while ((opt = ssh_getopt(argc, argv, "P:S:d:scu:r:hI",NULL)) 
         != (char)EOF)
    {
      switch (opt)
        {
        case 'c':
          params.client = TRUE;
          break;
        case 's':
          params.server = TRUE;
          break;
        case 'd':
          ssh_debug_set_level_string(ssh_optarg);
          break;
        case 'u':
	  user_buf = ssh_optarg;
          user_len = strlen(ssh_optarg);
          break;
        case 'I':
          params.no_identity = TRUE;
          break;
        case 'P':
	  params.local_listener_path = ssh_optarg;
	  break;
        case 'h':
          usage(0);
          break;
#ifdef SSHDIST_RADIUS
        case 'r':
	  params.radius_url = ssh_optarg;
          break;
#endif /* SSHDIST_RADIUS */
        default:
          usage(1);
          break;
        }
    }

#ifdef SSHDIST_TESTS_INPLACE
  if (user_buf == NULL)
    {
      user_buf = DEFAULT_USER_STRING;
      user_len = strlen(DEFAULT_USER_STRING);
    }

  if (params.radius_url == NULL) params.radius_url = DEFAULT_RADIUS_STRING; 
#endif /* SSHDIST_TESTS_INPLACE */

  if (params.server && (params.radius_url == NULL))
    {
      ssh_warning("EAP AKA-DASH test must use Radius when acting as a server");
      return 1;
    }

  return test_eap_run(program, &params, 
		      t_aka_dash_config_handler,
		      t_aka_dash_token_handler,
		      NULL, 
		      NULL);

}
#else /* SSHDIST_EAP_AKA_DASH */
int main(int argc, char **argv)
{
  fprintf(stderr, "EAP AKA-DASH not configured\n");
  exit(1);
}
#endif /* SSHDIST_EAP_AKA_DASH */
