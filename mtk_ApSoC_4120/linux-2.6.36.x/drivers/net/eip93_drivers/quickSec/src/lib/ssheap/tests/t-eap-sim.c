/*
  t-eap-sim.c

  Copyright:
          Copyright (c) 2007 SFNT Finland Oy.
  All Rights Reserved.
*/

#include <stdio.h>
#include "sshincludes.h"
#include "sshgetopt.h"
#include "ssheap.h"
#include "t-eap.h"
#include "t-eap-files.h"

static char *program;

static unsigned char *user_buf;
static size_t user_len;

#define SSH_DEBUG_MODULE "TestEapSIM"

#ifdef SSHDIST_EAP_SIM

#ifdef SSHDIST_TESTS_INPLACE
#define DEFAULT_RADIUS_STRING "radius://foo:foobar@172.30.4.78"
#define DEFAULT_USER_STRING "simuser"
#else /* SSHDIST_TESTS_INPLACE */
#define DEFAULT_RADIUS_STRING "radius://foo:foobar@1.2.3.4"
#define DEFAULT_USER_STRING "simuser"
#endif /* SSHDIST_TESTS_INPLACE */

void 
t_sim_config_handler(SshEap eap, void *context)
{
  SSH_DEBUG(SSH_D_HIGHOK, ("Accepting SIM method"));
  ssh_eap_accept_auth(eap, SSH_EAP_TYPE_SIM, 9);
}

void
t_sim_token_handler(SshEap eap, 
		    SshUInt8 type, 
		    SshBuffer buf,
		    SshEapToken token,
		    void *context)
{
  SshEapToken tinput;
  SshEapTokenType token_type;
  SshUInt8 sim_buffer[1024];
  int sim_len = 0;

  SSH_ASSERT(buf != NULL);

  tinput = (SshEapToken)ssh_buffer_ptr(buf);
  token_type = ssh_eap_get_token_type_from_buf(buf);

  switch (token_type)
    {
    case SSH_EAP_TOKEN_USERNAME:
      ssh_eap_init_token_username(token,
                                  user_buf,
                                  user_len);
      break;

    case SSH_EAP_TOKEN_SIM_CHALLENGE:

      sim_len = eap_read_sim_files(SSH_EAP_TYPE_SIM, 
				   tinput->token.buffer.dptr, 
				   tinput->token.buffer.len, 
				   sim_buffer,
				   sizeof(sim_buffer));

      /* Is there an error reading the file containing
	 the keys for this SIM authentication thingy. */
      if (sim_len == -1)
	{
	  SSH_DEBUG(SSH_D_ERROR, ("Could not read SIM keys. Please"
				  " re-check the existence of the "
				  "key file."));
	  token_type = SSH_EAP_TOKEN_NONE;
	  break;
	}

      token->token.buffer.dptr = sim_buffer;
      token->token.buffer.len  = sim_len;
      token->type              = SSH_EAP_TOKEN_SIM_CHALLENGE;
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
      ssh_warning("EAP SIM test must use Radius when acting as a server");
      return 1;
    }

  return test_eap_run(program, &params, 
		      t_sim_config_handler,
		      t_sim_token_handler,
		      NULL, 
		      NULL);
}
#else /* SSHDIST_EAP_SIM */
int main(int argc, char **argv)
{
  fprintf(stderr, "EAP SIM not configured\n");
  exit(1);
}
#endif /* SSHDIST_EAP_SIM */
