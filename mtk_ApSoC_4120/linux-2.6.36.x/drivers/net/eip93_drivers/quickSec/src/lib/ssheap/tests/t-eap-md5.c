/*
  t-eap-md5.c

  Copyright:
          Copyright (c) 2007 SFNT Finland Oy.
  All Rights Reserved.
*/

#include <stdio.h>
#include "sshincludes.h"
#include "sshgetopt.h"
#include "t-eap.h"

static char *program;

static unsigned char *secret_buf;
static unsigned char *user_buf;
static size_t secret_len;
static size_t user_len;


#define SSH_DEBUG_MODULE "TestEapMD5"

void
t_md5_destroy_handler(void *context)
{
  if (secret_buf) ssh_xfree(secret_buf);
  if (user_buf) ssh_xfree(user_buf);
}

void
t_md5_config_handler(SshEap eap, void *context)
{
  SSH_DEBUG(SSH_D_HIGHOK, ("Accepting MD5 method"));

  ssh_eap_accept_auth(eap, SSH_EAP_TYPE_MD5_CHALLENGE, 16);
}

void
t_md5_token_handler(SshEap eap, 
		    SshUInt8 type, 
		    SshBuffer buf,
		    SshEapToken token,
		    void *context)
{
  SshEapTokenType token_type;

  SSH_ASSERT(buf != NULL);

  token_type = ssh_eap_get_token_type_from_buf(buf);

  switch (token_type)
    {
    case SSH_EAP_TOKEN_USERNAME:
      ssh_eap_init_token_username(token,
                                  user_buf,
                                  user_len);
      break;

    case SSH_EAP_TOKEN_SHARED_SECRET:
      ssh_eap_init_token_secret(token,
				secret_buf,
                                secret_len);
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
   -p PASSWORD            set password to PASSWORD\n\
   -I                     skip identification request/response phase\n\
   -d LEVEL               set debug level string to LEVEL\n\
"
#ifdef SSHDIST_RADIUS
"\
   -r                     radius URL\n\
"
#endif /* SSHDIST_RADIUS */
         ,program);
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

  while ((opt = ssh_getopt(argc, argv, "P:d:p:scu:r:hI",NULL)) 
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
        case 'p':
          secret_buf = ssh_xstrdup(ssh_optarg);
          secret_len = strlen(ssh_optarg);
          break;
        case 'd':
          ssh_debug_set_level_string(ssh_optarg);
          break;
        case 'u':
          user_buf = ssh_xstrdup(ssh_optarg);
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

  return test_eap_run(program, &params, 
		      t_md5_config_handler,
		      t_md5_token_handler, 
		      t_md5_destroy_handler,
		      NULL);
}
