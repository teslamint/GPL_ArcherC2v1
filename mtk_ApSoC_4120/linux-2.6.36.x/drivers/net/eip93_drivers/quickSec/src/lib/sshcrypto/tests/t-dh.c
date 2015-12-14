/*
  File: t-dh.c

  Description:
        Test diffie hellman group speeds.

  Copyright:
        Copyright (c) 2002-2007 SFNT Finland Oy.
        All rights reserved
*/

#include "sshincludes.h"
#include "sshglobals.h"
#include "sshgetopt.h"
#include "sshcrypt.h"
#include "sshtimemeasure.h"

typedef struct SshDHGrpRec
{
  char *type;
  char *name;
  int str;
} *SshDHGrp;

#define SSH_DH_DEFAULT_ENTROPY_MULTIPLIER 3
#define SSH_DH_DEFAULT_TEST_COUNT 5

#define SSH_DEBUG_MODULE "tdh"

static struct SshDHGrpRec group_descr[] =
{
  {"dl-modp", "ssh-dl-modp-group-dsa-1024bit-1", 0x4d}
  ,{"dl-modp", "ssh-dl-modp-group-1024bit-1", 0x4d}
  ,{ "dl-modp", "ietf-ike-grp-modp-768", 0x42 }
  ,{ "dl-modp", "ietf-ike-grp-modp-1024", 0x4d}
  ,{ "dl-modp", "ietf-ike-grp-modp-1536", 0x5b}
  ,{ "dl-modp", "ietf-ike-grp-modp-2048", 110}
  ,{ "dl-modp", "ietf-ike-grp-modp-3072", 130}
  ,{ "dl-modp", "ietf-ike-grp-modp-4096", 150}
  ,{ "dl-modp", "ietf-ike-grp-modp-6144", 170}
  ,{ "dl-modp", "ietf-ike-grp-modp-8192", 190}
  ,{ "dl-modp", "ietf-ike-grp-modp-16384", 210}

  ,{ "dl-modp", "ietf-rfc5114-2-1-modp-1024-160", 80 }
  ,{ "dl-modp", "ietf-rfc5114-2-2-modp-2048-224", 112 }
  ,{ "dl-modp", "ietf-rfc5114-2-3-modp-2048-256", 112 }




#ifdef  SSHDIST_CRYPT_ECP 
  ,{ "ec-modp", "ssh-ec-modp-curve-155bit-1", 78}
  ,{ "ec-modp", "ssh-ec-modp-curve-155bit-2", 78}
  ,{ "ec-modp", "ssh-ec-modp-curve-175bit-1", 88}
  ,{ "ec-modp", "ssh-ec-modp-curve-175bit-2", 88}
  ,{ "ec-modp", "prime256v1", (128 + 2) / 3}
  ,{ "ec-modp", "secp384r1", (192 + 2) / 3}
  ,{ "ec-modp", "secp521r1", (261 + 2) / 3}
#endif /* SSHDIST_CRYPT_ECP */
};

static void
usage(void)
{
  printf("\
Usage: []OPTION...\n\
  -e        entropy multiplier\n\
  -n        number of operations\n\
  -h        Print this help and exit\n");
}

int main (int ac, char **av)
{
  int i, j, c;
  SshInt32 entmul = SSH_DH_DEFAULT_ENTROPY_MULTIPLIER;
  SshInt32 tcount = SSH_DH_DEFAULT_TEST_COUNT;
  SshDHGrp group;
  SshPkGroup g;

  while ((c = ssh_getopt(ac, av, "e:n:h", 
			 NULL))
         != EOF)
    {
      switch (c)
	{
	case 'e':
	  {
	    int tmp;
	    
	    tmp = atoi(ssh_optarg);
	    if (tmp < 1 || tmp > 255)
	      {
		printf("The entropy multiplier value must be from range 1-255\n");
		exit(1);
	      }
	    
	    entmul = tmp;
	    break;
	  }
	case 'n':
	  {
	    int tmp;
	    
	    tmp = atoi(ssh_optarg);
	    if (tmp < 1 || tmp > 65535)
	      {
		printf("The number of value must be from range 1-65535\n");
		exit(1);
	      }
	    
	    tcount = tmp;
	    break;
	  }
	case 'h': usage(); exit(0);
	}
    }

  if (ssh_crypto_library_initialize() != SSH_CRYPTO_OK)
    ssh_fatal("Cannot initialize the crypto library.");

  if (ssh_crypto_library_self_tests() != SSH_CRYPTO_OK)
    ssh_fatal("Crypto library self tests failed");

  /* Register some key types. */
#ifdef WITH_RSA
  ssh_pk_provider_register(&ssh_pk_if_modn);
#endif /* WITH_RSA */
  ssh_pk_provider_register(&ssh_pk_dl_modp);



#ifdef SSHDIST_CRYPT_ECP
  ssh_pk_provider_register(&ssh_pk_ec_modp);
#endif /* SSHDIST_CRYPT_ECP */

  for (j = 0; j < sizeof(group_descr) / sizeof(group_descr[0]); j++)
    {
      SshPkGroupDHSecret secret;
      unsigned char *agreed = NULL, *exchange = NULL;
      size_t alen, elen, rlen;
      struct SshTimeMeasureRec tmit = SSH_TIME_MEASURE_INITIALIZER;
      SshUInt32 usecs;
      SshCryptoStatus cret;

      group = &group_descr[j];

      if (!strcmp(group->type, "dl-modp"))
        cret =
          ssh_pk_group_generate(&g,
                                group->type,
                                SSH_PKF_PREDEFINED_GROUP, group->name,
                                SSH_PKF_DH, "plain",
                                SSH_PKF_RANDOMIZER_ENTROPY, 
                                group->str * entmul,
                                SSH_PKF_END);
      else
        cret =
          ssh_pk_group_generate(&g,
                                group->type,
                                SSH_PKF_PREDEFINED_GROUP, group->name,
                                SSH_PKF_DH, "plain",
                                SSH_PKF_END);

      if (cret != SSH_CRYPTO_OK)
        ssh_fatal("setting up group %s", group->name);

      elen = ssh_pk_group_dh_setup_max_output_length(g);
      if (elen == 0)
        ssh_fatal("group can not do diffie hellman", group->name);
      else
        exchange = ssh_xmalloc(elen);

      alen = ssh_pk_group_dh_agree_max_output_length(g);
      if (alen == 0)
        ssh_fatal("group can not do diffie hellman", group->name);
      else
        agreed = ssh_xmalloc(alen);

      ssh_time_measure_reset(&tmit);
      ssh_time_measure_start(&tmit);
      for (i = 0; i < tcount; i++)
        {

          if (ssh_pk_group_dh_setup(g, &secret, exchange, elen, &rlen)
              != SSH_CRYPTO_OK)
            ssh_fatal("diffie hellman setup failed for %s", group->name);

          if (ssh_pk_group_dh_agree(g,
                                    secret,
                                    exchange, elen, agreed, alen,
                                    &rlen) != SSH_CRYPTO_OK)
            ssh_fatal("diffie hellman agree failed for %s", group->name);

          if (rlen != alen)
            ssh_fatal("agreed length differs");
        }

      ssh_time_measure_stop(&tmit);
      usecs =
        (unsigned int)ssh_time_measure_get(&tmit,
                                           SSH_TIME_GRANULARITY_MICROSECOND);

      printf("group %s %d agreements in %ld usecs -> %2.4g/second\n",
             group->name,
             i, usecs,
             (double)(1.0 / ((1.0 / 1000000.0) * ((double)usecs / i))));

      ssh_xfree(agreed);
      ssh_xfree(exchange);

      ssh_pk_group_free(g);
    }

  ssh_crypto_library_uninitialize();
  ssh_util_uninit();

  return 0;
}
/* eof */
