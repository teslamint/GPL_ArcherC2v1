/*

  gentest.c

  Copyright:
          Copyright (c) 2002-2004 SFNT Finland Oy.
  All rights reserved.

  Testing those gen- prefixed files.

  */

#include "sshincludes.h"
#include "namelist.h"
#include "sshcrypt.h"
#include "sshtimemeasure.h"
#include "readfile.h"
#include "sshmp.h"
#include "sshdsprintf.h"
#include "sshgetopt.h"
#include "sshenum.h"
#include "sshregression.h"
#include "t-gentest.h"

#define SSH_DEBUG_MODULE "GenTestMain"

/* Location for the test script files, derived from environment
   variable srcdir (from automake), or "." if the variable was not
   set. */
char *srcpath = NULL;
/* Temporary; concatenation of srcpath and the script filename for
   current test module. */
char filename[128];

Boolean verbose = FALSE;

/******************** Misc. routines. ************************/

void hex_dump(unsigned char *cp, size_t len)
{
  int i;
  for (i = 0; i < len; i++)
    {
      printf("%02x", cp[i]);
    }
}

int hex_render(unsigned char *buf, int buf_size, int prec, void *datum)
{
  HexRender data = (HexRender) datum;
  int len, pos, i;

  pos = 0;

  SSH_DEBUG(15, ("buf=%p buf_size=%d prec=%d data.length=%d data.data=%p",
                 buf, buf_size,prec, data->length, data->data));

  /* not enough space? */
  len = data->length * 2;

  if (buf_size >= len)
    for (i = 0; i < data->length; i++)
      ssh_snprintf(buf + i * 2, buf_size - i * 2, "%02x", data->data[i]);
  else
    len = buf_size + 1;

  if (prec >= 0)
    if (len > prec)
      len = prec;

  return len;
}

void tstart(SshTimeMeasure tmit, char *fmt, ...)
{
  va_list ap;
  char buffer[1024];

  va_start(ap, fmt);
  ssh_vsnprintf(buffer, 1024, fmt, ap);
  va_end(ap);

  if (verbose)
    printf("Timing start: %s\n", buffer);

  ssh_time_measure_reset(tmit);
  ssh_time_measure_start(tmit);
}

void tstop(SshTimeMeasure tmit, char *fmt, ...)
{
  va_list ap;
  char buffer[1024];
  ssh_time_measure_stop(tmit);

  va_start(ap, fmt);
  ssh_vsnprintf(buffer, 1024, fmt, ap);
  va_end(ap);

  printf("@ %6.3f sec : %s\n",
         (double) ssh_time_measure_get(tmit,
                                       SSH_TIME_GRANULARITY_MILLISECOND) /
         1000.0,
         buffer);
}


void tstartn(SshTimeMeasure tmit, int total, char *fmt, ...)
{
  va_list ap;
  char buffer[1024];

  if (total > 0)
    {
      ssh_time_measure_reset(tmit);
      ssh_time_measure_start(tmit);
      return;
    }

  va_start(ap, fmt);
  ssh_vsnprintf(buffer, 1024, fmt, ap);
  va_end(ap);

  if (verbose) printf("Timing start: %s\n", buffer);

  ssh_time_measure_reset(tmit);
  ssh_time_measure_start(tmit);
}

int tstopn(SshTimeMeasure tmit, int total, char *fmt, ...)
{
  va_list ap;
  char buffer[1024];
  ssh_time_measure_stop(tmit);

  /* Just check that the operation takes at least some time. */
  if (ssh_time_measure_get(tmit, SSH_TIME_GRANULARITY_MILLISECOND) < 1000.0)
    {
      return 1;
    }

  va_start(ap, fmt);
  ssh_vsnprintf(buffer, 1024, fmt, ap);
  va_end(ap);

  printf("@ "
         "%6.3f sec / %5u ops = "
         "%6.4f sec / op = "
         "%5u ops / second: %s\n",
         (double) ssh_time_measure_get(tmit,
                                       SSH_TIME_GRANULARITY_MILLISECOND) /
         1000.0, total,

         ((double) ssh_time_measure_get(tmit,
                                        SSH_TIME_GRANULARITY_MILLISECOND) /
          1000.0)/(double)total,

         (int)
         (total / ((double) ssh_time_measure_get(tmit,
                                        SSH_TIME_GRANULARITY_MILLISECOND) /
                   1000.0)),

         buffer);
  return 0;
}

/****************************** Main ***************************************/

#define TEST_RANDOM (1 << 0)
#define TEST_HASH   (1 << 1)
#define TEST_MAC    (1 << 2)
#define TEST_CIPHER (1 << 3)
#define TEST_PKCS   (1 << 4)
#define TEST_MISC       (1 << 5)

const SshKeywordStruct t_gentest_test_flags[] =
  {
    { "all", TEST_RANDOM|TEST_HASH|TEST_MAC|TEST_CIPHER|TEST_PKCS },
    { "random", TEST_RANDOM },
    { "hash", TEST_HASH },
    { "mac", TEST_MAC },
    { "cipher", TEST_CIPHER },
    { "pkcs", TEST_PKCS },
    { "misc", TEST_MISC },
    { NULL }
  };

const SshKeywordStruct t_gentest_cipher_flags[] =
  {
    { "all", MODE_ECB|MODE_CBC|MODE_CFB|MODE_OFB },
    { "ecb", MODE_ECB },
    { "cbc", MODE_CBC },
    { "cfb", MODE_CFB },
    { "ofb", MODE_OFB },
    { NULL }
  };

/* Main function that calls all the tests above. */

int main(int argc, char *argv[])
{
  int opt;
  int len = 1024;
  int tests = 0L;
  int cipher_flags = MODE_CBC;
  char *debuglevel = NULL;
  Boolean speed_tests = FALSE, generate = FALSE;

  ssh_regression_init(&argc, &argv, "Generic crypto",
		      "kivinen@safenet-inc.com");

  while ((opt = ssh_getopt(argc, argv, "s:c:t:vd:l:Sg", NULL)) != EOF)
    {
      switch (opt)
        {
        case 'v':
          verbose = TRUE;
          break;
        case 't':
          tests |= ssh_find_keyword_number(t_gentest_test_flags, ssh_optarg);
          break;
        case 'c':
          cipher_flags |=
            ssh_find_keyword_number(t_gentest_cipher_flags, ssh_optarg);
          break;
        case 's':
          srcpath = ssh_optarg;
          break;
        case 'S':
          speed_tests = TRUE;
          break;
        case 'd':
          debuglevel = ssh_optarg;
          break;
        case 'g':
          generate = TRUE;
          break;
	case 'l':
	  len = atoi(ssh_optarg);
	  break;
        default:
          fprintf(stderr,
		  "usage: t-gentest [-d debuglevel] [-g] [-l buffer_len] "
                  "[-v] [-t testname]* [-c mode] [-S] [-s src_path]*\n");
          exit(1);
        }
    }

  if (ssh_crypto_library_initialize() != SSH_CRYPTO_OK)
    ssh_fatal("Crypto library initialization failed");

  if (debuglevel)
    ssh_debug_set_level_string(debuglevel);

  if (!tests)
    tests = TEST_RANDOM|TEST_HASH|TEST_MAC|TEST_CIPHER|TEST_PKCS|TEST_MISC;

  if (srcpath == NULL)
    {
      if ((srcpath = getenv("srcdir")) == NULL)
	{
	  ssh_warning("$srcdir not set, defaulting "
		      "script file location to `.'");
	  srcpath = ".";
	}
    }

#ifndef SSH_USE_CYCLE_COUNTING
  if (speed_tests)
    printf("(Cycle counting not available -- cycles/bytes fields "
           "are hence invalid.)\n");
#endif /* SSH_USE_CYCLE_COUNTING */

  /* Register some key types. */
  ssh_pk_provider_register(&ssh_pk_if_modn_generator);
#ifdef SSHDIST_CRYPT_GENPKCS_DH
  ssh_pk_provider_register(&ssh_pk_dl_modp_generator);
#endif /* SSHDIST_CRYPT_GENPKCS_DH */



#ifdef SSHDIST_CRYPT_ECP
  ssh_pk_provider_register(&ssh_pk_ec_modp_generator);
#endif /* SSHDIST_CRYPT_ECP */

#ifdef SSHDIST_IPSEC_HWACCEL_OCTEON
#ifdef ASM_PLATFORM_OCTEON
          ssh_regression_section("Octeon combined Cipher/Mac test");
          SSH_REGRESSION_TEST("Consistency test", 
			      octeon_combined_consistency_tests,
			      (len));
	  if (speed_tests)
	    octeon_combined_speed_tests(len);
#endif /* ASM_PLATFORM_OCTEON */
#endif /* SSHDIST_IPSEC_HWACCEL_OCTEON */

  if (generate)
    {

      ssh_fatal("Never generate test vectors with a distribution build.");


      printf("Generating static test vectors -- "
             "regression tests not executed.\n");

      printf("*** IMPORTANT: The generated test vectors must be merged with\n"
             "*** existing test vectors with care. Do not just "
                "copy over without\n"
             "*** thought.\n");

      if (tests & TEST_PKCS)
        {
          printf("Generating static pkcs test vectors..\n");

          if (!pkcs_import_export_tests_do("import-export.tests.created"))
            ssh_fatal("Could not generate PKCS key import/export "
                      "test vectors.");

          if (!pkcs_static_tests_do("pkcs.tests.created"))
            ssh_fatal("Could not generate PKCS test vectors.");
        }

      if (tests & TEST_MAC)
        {
          printf("Generatic MAC..\n");
          mac_static_tests_do("mac.tests.created");
        }

      if (tests & TEST_CIPHER)
        {
          printf("Generating cipher...\n");
          cipher_static_tests_do("cipher.tests.created");
        }
    }
  else if (speed_tests)
    {
      printf("Doing speed tests only -- regression tests not executed.\n");
      if (tests & TEST_CIPHER)
	{
	  printf("Doing cipher speed tests\n");
	  cipher_random_tests(TRUE, cipher_flags, len);
	  printf("Doing combined cipher and authentication speed tests\n");
	  encrypt_auth_speed_tests(len);
	}
      if (tests & TEST_HASH)
        hash_random_tests(TRUE, len);
      if (tests & TEST_MAC)
        mac_random_tests(TRUE, len);
      if (tests & TEST_PKCS)
        {
          pkcs_tests(TRUE);
          pkcs_random_tests(TRUE);
        }
    }
  else
    {
      if (tests & TEST_RANDOM)
        {
          char *supported, *name;
          const char *temp;

          ssh_regression_section("Random number test");
          supported = ssh_random_get_supported();
          temp = supported;

          while (temp)
            {
              name = ssh_name_list_get_name(temp);
              /* Skip always "device" and "pool" */
              if (strcmp(name, "device") != 0 && strcmp(name, "pool") != 0)
                SSH_REGRESSION_TEST(name, test_random, (name, 0L));
              ssh_free(name);
              temp = ssh_name_list_step_forward(temp);
            }

          ssh_free(supported);
        }

      if (tests & TEST_HASH)
        {
          ssh_snprintf(filename, sizeof(filename), "%s/hash.tests", srcpath);

          ssh_regression_section("Hash test");
          SSH_REGRESSION_TEST("Random test", hash_random_tests, (FALSE, len));
          SSH_REGRESSION_TEST("Static test", hash_static_tests, (filename));
          SSH_REGRESSION_TEST("ASN.1 encode test", hash_asn1_encode_test, ());
        }

      if (tests & TEST_MAC)
        {
          ssh_snprintf(filename, sizeof(filename), "%s/mac.tests", srcpath);
          ssh_regression_section("MAC tests");
          SSH_REGRESSION_TEST("Random test", mac_random_tests, (FALSE, len));
          SSH_REGRESSION_TEST("Static test", mac_static_tests, (filename));
        }

      if (tests & TEST_CIPHER)
        {
          ssh_snprintf(filename, sizeof(filename), "%s/cipher.tests", srcpath);

          ssh_regression_section("Cipher tests");
          SSH_REGRESSION_TEST("Random test", cipher_random_tests,
                              (FALSE, cipher_flags, len));
          SSH_REGRESSION_TEST("Static test", cipher_static_tests, (filename));

#ifdef SSHDIST_IPSEC_HWACCEL_OCTEON
#ifdef ASM_PLATFORM_OCTEON
          ssh_regression_section("Octeon combined Cipher/Mac test");
          SSH_REGRESSION_TEST("Consistency test", 
			      octeon_combined_consistency_tests,
			      (len));
	  if (speed_tests)
	    octeon_combined_speed_tests(len);
#endif /* ASM_PLATFORM_OCTEON */
#endif /* SSHDIST_IPSEC_HWACCEL_OCTEON */
	}

      if (tests & TEST_PKCS)
        {
          ssh_regression_section("Public-key tests");

          SSH_REGRESSION_TEST("Random tests", pkcs_random_tests, (FALSE));

          ssh_snprintf(filename, sizeof(filename),
                       "%s/import-export.tests", srcpath);
          SSH_REGRESSION_TEST("Static key import/export",
                              pkcs_import_export_tests, (filename));

          ssh_snprintf(filename, sizeof(filename), "%s/pkcs.tests", srcpath);
	  SSH_REGRESSION_TEST("Static tests", pkcs_static_tests, (filename));
#ifdef SSHDIST_CRYPT_DSA
          SSH_REGRESSION_TEST("FIPS DSS static tests",
                              fips_dss_static_tests, (FALSE));
#endif /* SSHDIST_CRYPT_DSA */
	  SSH_REGRESSION_TEST("PSS static tests", pss_static_tests, (FALSE));
	  SSH_REGRESSION_TEST("OAEP static tests", oaep_static_tests, (FALSE));
          SSH_REGRESSION_TEST("Selected tests", pkcs_tests, (FALSE));
#ifdef SSHDIST_CRYPT_GENPKCS_DH
          SSH_REGRESSION_TEST("Predefined groups",
                              predefined_groups_tests, ());
#endif /* SSHDIST_CRYPT_GENPKCS_DH */
	  SSH_REGRESSION_TEST("RSA e=3 signature forgery test",
			      pkcs_rsa_e_equal_3_signature_forgery_test, 
			      (FALSE)); 
#ifdef SSHDIST_CRYPT_ECP
          SSH_REGRESSION_TEST("ECP Diffie-Hellman tests", 
			      ecp_ietf_groups_diffie_hellman_test, (FALSE));
          SSH_REGRESSION_TEST("ECP DSA tests", 
			      ecp_ietf_groups_dsa_test, (FALSE));
#endif /* SSHDIST_CRYPT_ECP */
       }
      if (tests & TEST_MISC)
        {
          ssh_regression_section("Miscellaneous tests");

          SSH_REGRESSION_TEST("FIPS API non-FIPS library compliance",
                              misc_nonfips_tests, ());

        }
    }

  ssh_crypto_library_uninitialize();
  ssh_debug_uninit();

  ssh_regression_finish();
  exit(0);
}
