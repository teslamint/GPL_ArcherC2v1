/*
  File: t-genacc-speed.c

  Copyright:
          Copyright (c) 2008 SFNT Finland Oy.

  Timing program for generic accelerator.

*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshpk_i.h"
#include "sshtimemeasure.h"
#include "sshexternalkey.h"
#include "genaccprov.h"
#include "sshglobals.h"
#include "sshfsm.h"
#include "ssheloop.h"
#include "sshoperation.h"
#include "sshtimeouts.h"
#include "sshgetput.h"
#include "sshdsprintf.h"
#include "sshgetopt.h"

#define SSH_DEBUG_MODULE "SshEkTGenacc"

static SshUInt32 group_entropy = 0;
static SshUInt32 number_of_operations = 100;
static Boolean use_dh_randomizers = FALSE;
static Boolean accelerator_test = TRUE;
static SshExternalKey externalkey = NULL;
static char *provider_name = NULL;

/* A dummy timeout to prevent the event loop from returning. */
void dummy_timeout(void *ctx)
{
  ssh_xregister_timeout(1, 0, dummy_timeout, NULL);
}

void uninit_test(int exit_value)
{
  ssh_cancel_timeouts(dummy_timeout, NULL);
#ifdef HAVE_THREADS
  ssh_threaded_timeouts_uninit();
#endif /* HAVE_THREADS */
  ssh_event_loop_uninitialize();
  ssh_crypto_library_uninitialize();
  ssh_util_uninit();
  exit(exit_value);
}

/*************************** GROUP TESTS ********************************/


typedef struct SshDHGrpRec
{
  char *type;
  char *name;
  SshUInt32 size;
  int group_number;
} *SshDHGrp;

#define no_of_fixed_groups 4
struct SshDHGrpRec group_descr[no_of_fixed_groups] =
  {
    { "dl-modp", "ietf-ike-grp-modp-768",   768, 1 },
    { "dl-modp", "ietf-ike-grp-modp-1024", 1024, 2 },
    { "dl-modp", "ietf-ike-grp-modp-1536", 1536, 5 },
    { "dl-modp", "ietf-ike-grp-modp-2048", 2048, 6 }
  };


typedef struct GroupTesterRec
{
  SshExternalKey externalkey;
  SshTimeMeasure timer;
  Boolean get_test;
  SshPkGroup unaccel_group;
  SshPkGroup group;
  SshPkGroupDHSecret secret;
  SshPkGroupDHSecret copy_secret;
  SshUInt32 operations_pending;
  SshUInt32 operations_left;
  SshUInt32 operations_done;
  SshUInt32 total_operations;
  SshUInt32 randomizer_iterations;
  char *name;
  char *group_path;
  unsigned char *exchange;
  unsigned char *agreed;
  size_t elen, alen;
  unsigned char *unaccel_agreed;
  size_t unaccel_alen;
  size_t group_entropy;
} *GroupTester;



/******************* Benchmark test for DH groups ***********************/

/* Forward declarations */
void print_group_stats(GroupTester ctx);
void dh_agree_cb(SshCryptoStatus status,
                        const unsigned char *agreed,
                        size_t alen,
                        void *context);
void dh_setup_cb(SshCryptoStatus status,
                        SshPkGroupDHSecret secret,
                        const unsigned char *exchange,
                        size_t elen,
                        void *context);
void group_test_do(void *context);
void get_acc_group_cb(SshEkStatus status,
                             SshPkGroup group,
                             void *context);

/************************************************************************/


void group_test(SshExternalKey externalkey,
		const char *provider_name,
		unsigned int group_number)
{
  int j, entropy;
  SshDHGrp grp;
  SshPkGroup group;
  GroupTester tester;
  
  for (j = 0; j < no_of_fixed_groups; j++)
    {
      if (group_number == group_descr[j].group_number)
        break;
      
      if (j == no_of_fixed_groups - 1)
        {
          printf("Invalid group number [%d] supplied.\n"
                 "The supported group numbers are 1, 2, 5, and 6.\n",
                 group_number);
          exit(1);
        }
    }

  tester = ssh_xcalloc(1, sizeof(*tester));

  grp = &group_descr[j];

  entropy = (group_entropy < grp->size) ? group_entropy : grp->size;

  /* Generate a software Diffie-Hellman group. */
  if (ssh_pk_group_generate(&group,
                            grp->type,
                            SSH_PKF_PREDEFINED_GROUP, grp->name,
                            SSH_PKF_RANDOMIZER_ENTROPY, entropy,
                            SSH_PKF_DH, "plain",
                            SSH_PKF_END) != SSH_CRYPTO_OK)
    ssh_fatal("setting up group %s", grp->name);

  tester->unaccel_group = group;
  tester->externalkey = externalkey;
  tester->name = ssh_strdup(grp->name);
  tester->total_operations = number_of_operations;
  tester->operations_left = number_of_operations;
  tester->timer = ssh_time_measure_allocate();

  if (entropy == 0)
    tester->group_entropy = grp->size;
  else
    tester->group_entropy = entropy;

  /* Generate an accelerated Diffie-Hellman group from the
     corresponding software group. */
  ssh_ek_generate_accelerated_group(externalkey, provider_name,
                                    group, get_acc_group_cb, tester);
}

void group_test_try_start(void *context);

void get_acc_group_cb(SshEkStatus status,
                             SshPkGroup group,
                             void *context)
{
  GroupTester tester = context;
  SshPkGroup r_group;
  SshCryptoStatus stat;
  int i;

  if (status != SSH_EK_OK)
    ssh_fatal("Failed to generate an accelerated group");

  tester->group = group;

  if (use_dh_randomizers)
    {
      SSH_DEBUG(4, ("Generating randomizers"));

      r_group = accelerator_test ? tester->group : tester->unaccel_group;

      for (i = 0; i < tester->total_operations; i++)
	{
	  stat = ssh_pk_group_generate_randomizer(r_group);
	  if (stat != SSH_CRYPTO_OK)
	    ssh_fatal("Cannot generate randomizer for the group");
	}
    }

  ssh_xregister_timeout(0, 100, group_test_try_start, tester);
}

void group_test_try_start(void *context)
{
  GroupTester tester = context;
  SshPkGroup group;

  group = accelerator_test ? tester->group : tester->unaccel_group;
  tester->randomizer_iterations++;

  SSH_DEBUG(5, ("Now have %d randomizers",
		ssh_pk_group_count_randomizers(group)));

  /* If using randomizers, wait until they are all generated */
  if (use_dh_randomizers &&
      tester->randomizer_iterations < 10 &&
      ssh_pk_group_count_randomizers(group) < tester->total_operations)
    {
      ssh_xregister_timeout(0, 100, group_test_try_start, tester);
      return;
    }

  if (use_dh_randomizers)
    ssh_warning(" %d randomizers are generated, now starting "
		"Diffie-Hellman operations",
		ssh_pk_group_count_randomizers(group));

  ssh_time_measure_start(tester->timer);

  group_test_do(tester);
}

void group_test_do(void *context)
{
  GroupTester tester = context;
  SshPkGroup group;

  group = accelerator_test ? tester->group : tester->unaccel_group;

  tester->operations_pending++;
  tester->operations_left--;

  SSH_DEBUG(5, ("Start: Pending %d, ops left %d", tester->operations_pending,
		tester->operations_left));

  ssh_pk_group_dh_setup_async(group, dh_setup_cb, tester);

  if (tester->operations_left)
    ssh_xregister_timeout(0, 0, group_test_do, tester);
}


void dh_setup_cb(SshCryptoStatus status,
                        SshPkGroupDHSecret secret,
                        const unsigned char *exchange,
                        size_t elen,
                        void *context)
{
  GroupTester tester = context;
  SshPkGroup group;

  if (status != SSH_CRYPTO_OK)
    ssh_fatal("The DH setup operation has failed with status %d", status);

  group = accelerator_test ? tester->group : tester->unaccel_group;

  tester->secret = secret;

  ssh_pk_group_dh_agree_async(group, tester->secret,
                              exchange, elen,
                              dh_agree_cb, tester);
}

static void group_timer_free(void *context)
{
  GroupTester tester = context;

  ssh_time_measure_free(tester->timer);
  ssh_free(tester);

  uninit_test(0);
}

void group_timer_finish(void *context)
{
  GroupTester tester = context;

  ssh_pk_group_free(tester->group);
  ssh_pk_group_free(tester->unaccel_group);
  ssh_free(tester->name);
  ssh_ek_free(tester->externalkey, group_timer_free, tester);  
}

void dh_agree_cb(SshCryptoStatus status,
                        const unsigned char *agreed,
                        size_t alen,
                        void *context)
{
  GroupTester tester = context;

  tester->operations_pending--;
  tester->operations_done++;

  if (status != SSH_CRYPTO_OK)
    ssh_fatal("DH agree operation has failed with status %d", status);

  SSH_DEBUG(5, ("Pending %d, ops left %d", tester->operations_pending,
		tester->operations_left));


  if (tester->operations_pending == 0 && tester->operations_left == 0)
    {
      SshUInt64 secs;
      SshUInt32 nanos;
      SshUInt32 s;
      ssh_time_measure_get_value(tester->timer,
                                 &secs, &nanos);
      s = (SshUInt32)secs;
      SSH_DEBUG(4, ("DH test completed in %ds and %dns", s, nanos));
      print_group_stats(tester);

      ssh_xregister_timeout(0, 0, group_timer_finish, tester);
      return;      
    }
}

void print_group_stats(GroupTester ctx)
{
  SshUInt64 s;
  SshUInt32 ns, sec, total;

  ssh_time_measure_get_value(ctx->timer, &s, &ns);
  sec = (SshUInt32)s;

  total = sec * 1000 + (ns / 1000000);

  printf("Time consumed: %ld milliseconds, for %d Diffie-Hellman operations "
         "using group %s and %d bit exponents\n",
         (long)total, (int)ctx->operations_done, 
	 ctx->name, (int)ctx->group_entropy);
}

/********************** PUBLIC KEY TESTS ********************************/

/************************************************************************
  The following key generation routine is borrowed from the crypto
  library tests.
*************************************************************************/

typedef struct
{
  char *key_type;
  char *sign;
  char *encrypt;
  unsigned int size;
} PkcsInfo;

PkcsInfo pkcs_info[] = {
  { "if-modn", "rsa-pkcs1-none",  "rsa-pkcs1-none",  1024 },
  { "if-modn", "rsa-pss-md5",  "rsa-pkcs1-none",   1027 },
  { "if-modn", "rsa-pkcs1-none",  "rsa-pkcs1-none",  1025 },
  { "if-modn", "rsa-pkcs1-md5",  "rsa-pkcs1-none",   1319 },
  { "if-modn", "rsa-pkcs1-sha1", NULL, 1025 },
  { "if-modn", "rsa-pkcs1-md5",  "rsa-pkcs1-none",   1024 },
  { "if-modn", "rsa-pkcs1-sha1", NULL, 1024 },
  { "if-modn", "rsa-pss-sha1",  NULL,   1024 },
  { "if-modn", "rsa-pkcs1-sha1", "rsa-pkcs1v2-oaep", 1024 },
  { "dl-modp", "dsa-nist-sha1",  NULL,               1024 },
  { NULL }
};

SshPrivateKey pkcs_make_prvkey(PkcsInfo *info, unsigned int key_size)
{
  unsigned char *buf, *tmp[10], *k;
  unsigned int size;
  SshPrivateKey prv;
  SshCryptoStatus status;
  int i;

  ssh_dsprintf(&buf, "%s{", info->key_type);

  /* Generate the key. */
  i = 0;
  if (info->sign)
    {
      ssh_dsprintf(&tmp[i], "sign{%s}", info->sign);
      i++;
    }
  if (info->encrypt)
    {
      ssh_dsprintf(&tmp[i], "encrypt{%s}", info->encrypt);
      i++;
    }
  tmp[i] = NULL;

  for (i = 0; tmp[i]; i++)
    {
      if (i > 0)
        ssh_dsprintf(&k, "%s,%s", buf, tmp[i]);
      else
        ssh_dsprintf(&k, "%s%s", buf, tmp[i]);
      ssh_xfree(buf);
      ssh_xfree(tmp[i]);
      buf = k;
    }
  ssh_dsprintf(&k, "%s}", buf);
  ssh_xfree(buf);
  buf = k;

  SSH_DEBUG(10, ("Calling prv generate"));

  size = (key_size != 0) ? key_size : info->size;

  status = ssh_private_key_generate(&prv,
                                    buf,
                                    SSH_PKF_SIZE, size,
                                    SSH_PKF_END);

  SSH_DEBUG(10, ("Calling prv generate done"));

  ssh_free(buf);

  if (status != SSH_CRYPTO_OK)
    return NULL;

  return prv;
}

typedef struct KeyTesterRec
{
  SshTimeMeasure timer;
  SshExternalKey externalkey;
  char *provider_name;
  PkcsInfo *info;

  /* The unaccelerated software keys. */
  SshPrivateKey unaccel_prvkey;
  SshPublicKey unaccel_pubkey;

  /* The accelerated public key. */
  SshPublicKey pubkey;

  /* The accelerated private key. */
  SshPrivateKey prvkey;

  unsigned char *a, *b, *c, *ciphertext;
  size_t a_len, b_len, c_len, len, ciphertextlen;
  size_t ciphertext_len_return;
  size_t plaintext_len_return;

  unsigned char *data;
  size_t datalen;
  unsigned char *signature;
  size_t signaturelen;

  /* Some scheme information. */
  const char *sign_scheme;
  const char *enc_scheme;

  Boolean signature_test;
  SshUInt32 operations_pending;
  SshUInt32 operations_left;
  SshUInt32 operations_done;
} *KeyTester;


/************** Benchmark tests for public key operations ****************/

void get_prvkey_cb(SshEkStatus status, SshPrivateKey prvkey,
                          void *context);
void get_pubkey_cb(SshEkStatus status, SshPublicKey pubkey,
                          void *context);
void private_key_sign(void *context);
void public_key_encrypt(void *context);
void prv_sign_done(SshCryptoStatus status,
                          const unsigned char *data,
                          size_t data_len,
                          void *context);
void verify_done(SshCryptoStatus status,
                        void *context);
void decrypt_done(SshCryptoStatus status,
                         const unsigned char *data,
                         size_t data_len,
                         void *context);
void pub_encrypt_done(SshCryptoStatus status,
                             const unsigned char *data,
                             size_t data_len,
                             void *context);
void print_key_stats(KeyTester ctx);


/************************************************************************/


void key_test(SshExternalKey externalkey,
		     const char *provider_name, Boolean signature,
		     unsigned int key_len, const char *scheme)
{
  SshPrivateKey private_key;
  SshPublicKey  public_key;
  KeyTester tester;
  PkcsInfo *info;
  int index;

  for (index = 0; pkcs_info[index].key_type; index++)
    {
      if (signature)
        {
          if (pkcs_info[index].sign && !strcmp(pkcs_info[index].sign, scheme))
            break;
        }
      else
        {
          if (pkcs_info[index].encrypt && 
	      !strcmp(pkcs_info[index].encrypt, scheme))
            break;
        }
    }

  if (pkcs_info[index].key_type == NULL)
    {
      if (signature)
        printf("Invalid signature scheme [%s] supplied.\n"
               "The supported schemes are rsa-pkcs1-sha1, rsa-pkcs1-md5, "
               "rsa-pkcs1-none, dsa-nist-sha1\n", scheme);

      else
        printf("Invalid encryption scheme [%s] supplied.\n"
               "The supported schemes are rsa-pkcs1-none\n", scheme);
      exit(1);
    }

  info = &pkcs_info[index];

  tester = ssh_xcalloc(1, sizeof(*tester));
  tester->externalkey = externalkey;
  tester->provider_name = ssh_xstrdup(provider_name);
  tester->sign_scheme =  info->sign;
  tester->enc_scheme =  info->encrypt;
  tester->info =  info;
  tester->timer = ssh_time_measure_allocate();
  tester->operations_left = number_of_operations;

  if (signature)
    tester->signature_test =  TRUE;

  /* Generate a private key */
  private_key = pkcs_make_prvkey(info, key_len);
  if (private_key == NULL)
    ssh_fatal("error: key generation failed.");

  /* Get the public key */
  if (ssh_private_key_derive_public_key(private_key, &public_key) !=
      SSH_CRYPTO_OK)
    ssh_fatal("error: public key derivation failed.");

  tester->unaccel_prvkey = private_key;
  tester->unaccel_pubkey = public_key;

  /* Generate the accelerated private key from the software key. */
  ssh_ek_generate_accelerated_private_key(externalkey, provider_name,
                                          private_key, get_prvkey_cb,
                                          tester);
}

void get_prvkey_cb(SshEkStatus status,
                          SshPrivateKey prvkey,
                          void *context)
{
  KeyTester tester = context;

  if (status != SSH_EK_OK)
    ssh_fatal("Failed to generate an accelerated private key");

  tester->prvkey = prvkey;

  /* Generate the accelerated public key from the software key. */
  ssh_ek_generate_accelerated_public_key(tester->externalkey,
                                         tester->provider_name,
                                         tester->unaccel_pubkey,
                                         get_pubkey_cb,
                                         tester);
}

void get_pubkey_cb(SshEkStatus status,
                          SshPublicKey pubkey,
                          void *context)
{
  KeyTester tester = context;

  if (status != SSH_EK_OK)
    ssh_fatal("Failed to generate an accelerated group");

  tester->pubkey = pubkey;

  ssh_time_measure_start(tester->timer);

  if (tester->signature_test)
    ssh_xregister_timeout(0, 0, private_key_sign, tester);
  else
    ssh_xregister_timeout(0, 0, public_key_encrypt, tester);
}

/************************* Signature Test **********************************/

#define PLAIN_TEXT "'Please sign this short text.'"


void private_key_sign(void *context)
{
  KeyTester  tester = context;
  SshPrivateKey key;

  key = accelerator_test ? tester->prvkey : tester->unaccel_prvkey;

  tester->operations_pending++;
  tester->operations_left--;

  ssh_private_key_sign_async(key,
                             (unsigned char *)
                             PLAIN_TEXT,
                             strlen(PLAIN_TEXT) + 1,
                             prv_sign_done,
                             tester);

  if (tester->operations_left)
    ssh_xregister_timeout(0, 0, private_key_sign, tester);
}


void prv_sign_done(SshCryptoStatus status,
                          const unsigned char *data,
                          size_t data_len,
                          void *context)
{
  KeyTester tester = context;
  SshPublicKey key;

  key = accelerator_test ? tester->pubkey : tester->unaccel_pubkey;

  if (status != SSH_CRYPTO_OK)
    ssh_fatal("Private key sign operation failed");

  /* We time the combined operations of signature and verification. Replace
     '#if 0' by '#if 1' if you want to time the signature operation only */
#if 0
  verify_done(SSH_CRYPTO_OK, tester);
#else
  ssh_public_key_verify_async(key, data, data_len,
                              (unsigned char *)PLAIN_TEXT,
                              strlen(PLAIN_TEXT) + 1,
                              verify_done,
                              tester);
#endif /* 0 */
}


static void key_timer_free(void *context)
{
  KeyTester tester = context;

  ssh_time_measure_free(tester->timer);
  ssh_free(tester->provider_name);
  ssh_free(tester);

  uninit_test(0);
}

void key_timer_finish(void *context)
{
  KeyTester tester = context;
  
  ssh_private_key_free(tester->prvkey);
  ssh_public_key_free(tester->pubkey);
  ssh_private_key_free(tester->unaccel_prvkey);
  ssh_public_key_free(tester->unaccel_pubkey);
  ssh_ek_free(tester->externalkey, key_timer_free, tester);  
}

void verify_done(SshCryptoStatus status,
                        void *context)
{
  KeyTester tester = context;
  tester->operations_pending--;
  tester->operations_done++;

  if (status != SSH_CRYPTO_OK)
    ssh_fatal("Public key verify operation failed");

  if (tester->operations_left == 0 && tester->operations_pending == 0)
    {
      SshUInt64 secs;
      SshUInt32 nanos;
      SshUInt32 s;
      ssh_time_measure_get_value(tester->timer,
                                 &secs, &nanos);
      s = (SshUInt32)secs;
      SSH_DEBUG(3, ("Signature test completed in %ds and %dns", s, nanos));
      print_key_stats(tester);
  
      ssh_xregister_timeout(0, 0, key_timer_finish, tester);
    }
}

/************************* Encryption Test **********************************/

#define ENCRYPT_TEXT "Please encrypt this short text."

void public_key_encrypt(void *context)
{
  KeyTester  tester = context;
  SshPublicKey key;

  key = accelerator_test ? tester->pubkey : tester->unaccel_pubkey;

  tester->operations_pending++;
  tester->operations_left--;

  ssh_public_key_encrypt_async(key,
                               (unsigned char *)
                               ENCRYPT_TEXT,
                               strlen(ENCRYPT_TEXT) + 1,
                               pub_encrypt_done,
                               tester);

  if (tester->operations_left)
    ssh_xregister_timeout(0, 0, public_key_encrypt, tester);
}

void pub_encrypt_done(SshCryptoStatus status,
                             const unsigned char *data,
                             size_t data_len,
                             void *context)
{
  KeyTester tester = context;
  SshPrivateKey key;

  key = accelerator_test ? tester->prvkey : tester->unaccel_prvkey;

  if (status != SSH_CRYPTO_OK)
    ssh_fatal("Public key encrypt operation failed");

  ssh_private_key_decrypt_async(key, data, data_len,
                                decrypt_done, tester);

}

void decrypt_done(SshCryptoStatus status,
                         const unsigned char *data,
                         size_t data_len,
                         void *context)
{
  KeyTester tester = context;

  tester->operations_pending--;
  tester->operations_done++;

  if (status != SSH_CRYPTO_OK)
    ssh_fatal("Decrypt operation failed");

  if (data_len != strlen(ENCRYPT_TEXT) + 1 ||
      memcmp(data, (unsigned char *)ENCRYPT_TEXT, data_len))
    ssh_fatal("Decrypted plaintext does not match original");

  if (tester->operations_left == 0 && tester->operations_pending == 0)
    {
      SshUInt64 secs;
      SshUInt32 nanos;
      SshUInt32 s;
      ssh_time_measure_get_value(tester->timer,
                                 &secs, &nanos);
      s = (SshUInt32)secs;
      SSH_DEBUG(3, ("Encryption test completed in %ds and %dns", s, nanos));
      print_key_stats(tester);

      ssh_xregister_timeout(0, 0, key_timer_finish, tester);
    }
}

void print_key_stats(KeyTester ctx)
{
  SshUInt64 s;
  SshUInt32 ns, sec, total;

  ssh_time_measure_get_value(ctx->timer, &s, &ns);
  sec = (SshUInt32)s;

  total = sec * 1000 + (ns / 1000000);

  printf("Time consumed: %ld milliseconds, for %d operations "
         "using scheme %s\n", (long)total, (int)ctx->operations_done,
         ctx->signature_test ? ctx->sign_scheme : ctx->enc_scheme);
}

/*******************************************************************/

void usage()
{
  char *str;
  printf("Usage: t-genacc [options] device-name\n"
         "-i device info\n"
         "-m number of operations used in performing timing tests "
         "(default = 100)\n"
         "-g [IKE group number] a predefined IKE group\n"
         "-x the Diffie-Hellman randomizer entropy (default = 0)\n"
         "-s [scheme] perform timing test for the specified "
         "signature scheme\n"
         "-e [scheme] perform timing test for the specified "
         "encryption scheme\n"
         "-l bit length of private key to generate\n"
         "-R use DH randomizers for the group timing test\n"
         "-a turn acceleration off for timing tests\n"
         "-d debuglevel\n");

  str = ssh_acc_device_get_supported();
  printf("\nThe supported device names are %s\n", str);
  ssh_free(str);
}


int main(int ac, char **av)
{
  SshUInt32 num_providers;
  SshEkStatus status;
  SshEkProvider provider_array;
  int opt, group_number = 0;
  unsigned int key_len = 0;
  char *sname;
  char *device_name = NULL, *device_info = NULL;
  char *init_str, *scheme = NULL;
  Boolean signature = FALSE;
  Boolean encryption = FALSE;
  Boolean group = FALSE;
  
  while ((opt = ssh_getopt(ac, av, "ae:ts:g:hm:d:i:x:l:R", NULL)) != EOF)
    {
      switch (opt)
        {
        case 'i':
          device_info = ssh_optarg;
          break;
        case 'a':
          accelerator_test = FALSE;
          break;
        case 'x':
          group_entropy = atoi(ssh_optarg);
          break;
        case 'R':
          use_dh_randomizers = TRUE;
          break;
        case 'e':
          scheme = ssh_optarg;
          encryption = TRUE;
          break;
        case 's':
          scheme = ssh_optarg;
          signature = TRUE;
          break;
        case 'l':
          key_len = atoi(ssh_optarg);
          break;
        case 'g':
          group_number = atoi(ssh_optarg);
          group = TRUE;
          break;
        case 'm':
          number_of_operations = atoi(ssh_optarg);
          break;
        case 'd':
          ssh_debug_set_level_string(ssh_optarg);
          break;
        default:
        case 'h':
          usage();
          exit(1);
        }
    }
  ac -= ssh_optind;
  av += ssh_optind;

  device_name = *av;

  if (device_name == NULL)
    return 0;

  ssh_event_loop_initialize();

#ifdef HAVE_THREADS
  ssh_threaded_timeouts_init();
#endif /* HAVE_THREADS */

  externalkey = ssh_ek_allocate();

  /* Initialize the crypto library. */
  if (ssh_crypto_library_initialize() != SSH_CRYPTO_OK)
    ssh_fatal("Cannot initialize the crypto library");

  ssh_dsprintf((unsigned char **) &init_str, 
	       "name(%s),device-info(%s),rsa-crt(no)",
               device_name, device_info);

  SSH_DEBUG(4, ("The init string is %s\n", init_str));

  /* Add the provider */
  if ((status = ssh_ek_add_provider(externalkey, "genacc",
                                    init_str,
                                    NULL,
                                    SSH_EK_PROVIDER_FLAG_KEY_ACCELERATOR,
                                    &sname)) != SSH_EK_OK)
    ssh_fatal("Unable to add the provider");

  ssh_free(init_str);
  ssh_free(sname);

  /* Get all the registered providers. */
  if (!ssh_ek_get_providers(externalkey, &provider_array, &num_providers))
    ssh_fatal("Cannot get the providers");

  provider_name = (char *) (provider_array[0]).short_name;
  ssh_free(provider_array);

  ssh_xregister_timeout(0, 0, dummy_timeout, NULL);

  if (group)
    {
      /* Run the group timing tests. */
      SSH_DEBUG(5, ("Now starting the DH group timing tests for "
		    " provider %s\n", provider_name));
      group_test(externalkey, provider_name, group_number);
    }
  else if (signature)
    {
      /* Run the signature timing tests.*/
      SSH_DEBUG(5, ("Now starting the signature timing tests for "
		    "provider %s and scheme %s", provider_name, scheme));
      key_test(externalkey, provider_name, TRUE, key_len, scheme);
    }
  else if (encryption)
    {
      /* Run the encryption timing tests.*/
      SSH_DEBUG(5, ("Starting encryption timing tests for provider %s "
		    "and scheme %s", provider_name, scheme));

      key_test(externalkey, provider_name, FALSE, key_len, scheme);
    }
  else
    return 0;
    
  ssh_event_loop_run();
  return 0;
}
