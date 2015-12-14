/*

t-key-export.c

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
                   All rights reserved

  A simple utility progrma to test the import and export of private 
  keys using the ssh_private_key_[export, import]_with_passphrase() 
  interface.
*/

#include "sshincludes.h"
#include "sshgetopt.h"
#include "sshfileio.h"
#include "sshmp.h"
#include "sshcrypt.h"
#include "sshcryptoaux.h"

#define SSH_DEBUG_MODULE "TKeyExport"


void usage(void)
{
  fprintf(stderr, "Usage: t-key-export [options] FILE\n"
         "-i             : import a private key from FILE\n"
         "-e             : export a private key to FILE\n"
         "-v             : verbose output\n"
         "-t KEY TYPE    : key type when generating, either 'rsa' or 'dsa'\n"
         "-s KEY SIZE    : key size to generate\n"
         "-p PASSPHRASE  : passphrase\n"
         "-d DEBUG LEVEL : debuglevel\n");
}


int main(int argc, char *argv[])
{
  SshPrivateKey key = NULL;
  SshCryptoStatus status;
  Boolean verbose, export;
  SshMPIntegerStruct n, e, p, q, u, d, x, y, g;
  char *passphrase = "", *file_name = NULL, *key_type = "rsa";
  unsigned int key_size = 1024;
  unsigned char *buf = NULL;
  size_t buf_len;
  int opt;

  verbose = export = FALSE;

  while ((opt = ssh_getopt(argc, argv, "vt:s:d:p:ie", NULL)) != EOF)
    {
      switch (opt)
        {
        case 'd':
          ssh_debug_set_level_string(ssh_optarg);
          break;

        case 'p':
          passphrase = ssh_optarg;
          break;
	  
        case 'v':
          verbose = TRUE;
          break;

        case 't':
          key_type = ssh_optarg;
          break;

        case 's':
          key_size = atoi(ssh_optarg);
          break;
	  
	case 'e':
	  export = TRUE;
	  break;

	case 'i':
	  export = FALSE;
	  break;

	  break;
        default:
	  usage();
          exit(1);
        }
    }

  argc -= ssh_optind;
  argv += ssh_optind;

  file_name = *argv;
  
  if (file_name == NULL)
    {
      usage();
      exit(0);
    }
  
  if (ssh_crypto_library_initialize() != SSH_CRYPTO_OK)
    ssh_fatal("Crypto library initialization failed");

  ssh_mprz_init(&n);
  ssh_mprz_init(&e);
  ssh_mprz_init(&p);
  ssh_mprz_init(&q);
  ssh_mprz_init(&u);
  ssh_mprz_init(&d);
  ssh_mprz_init(&x);
  ssh_mprz_init(&y);
  ssh_mprz_init(&g);

  if (export)
    {
      if (!strcmp(key_type, "rsa"))
	{
	  status = ssh_private_key_generate(&key, 
					    "if-modn{sign{rsa-pkcs1-sha1}}",
					    SSH_PKF_SIZE, key_size,
					    SSH_PKF_END);
	  if (status != SSH_CRYPTO_OK)
	    {
	      fprintf(stderr, "Cannot generate a private key\n");
	      goto fail;   
	    }
	}
      else if (!strcmp(key_type, "dsa")) 
	{
	  status = ssh_private_key_generate(&key, 
					    "dl-modp{sign{dsa-nist-sha1}}",
					    SSH_PKF_SIZE, key_size,
					    SSH_PKF_END);
	  if (status != SSH_CRYPTO_OK)
	    {
	      fprintf(stderr, "Cannot generate a private key\n");
	      goto fail; 
	    }
	}	
      else
	{
	  fprintf(stderr, "Unsupported key tpye\n");
	  goto fail; 
	}

      SSH_ASSERT(key);      

      status = ssh_private_key_export_with_passphrase(key, "aes-cbc",
						      passphrase,
						      &buf, &buf_len);
      
      if (status != SSH_CRYPTO_OK)
	{
	  fprintf(stderr, "Cannot export the private key\n");
	  goto fail; 
	}
      
      if (!ssh_write_file(file_name, buf, buf_len))
	ssh_fatal("Cannot write the key to file");
    }
  else
    {
      if (!ssh_read_file(file_name, &buf, &buf_len))
	ssh_fatal("Cannot read from file");
      
      status = ssh_private_key_import_with_passphrase(buf, buf_len, 
						      passphrase,
						      &key);
      
      if (status != SSH_CRYPTO_OK)
	{
	  fprintf(stderr, "Cannot import the private key (%s)\n", 
		  ssh_crypto_status_message(status));
	  exit(1);	  
	}
    }
  
  
  if (key && verbose)
    {
      char *key_type;
      char *str;
      status = ssh_private_key_get_info(key, 
					SSH_PKF_KEY_TYPE, &key_type,
					SSH_PKF_END);
      
      if (status != SSH_CRYPTO_OK)
	goto fail;

      if (!strcmp(key_type, "if-modn"))
	{
	  status = ssh_private_key_get_info(key, 
					    SSH_PKF_MODULO_N, &n,
					    SSH_PKF_PUBLIC_E, &e,
					    SSH_PKF_PRIME_P, &p,
					    SSH_PKF_PRIME_Q, &q,
					    SSH_PKF_INVERSE_U, &u,
					    SSH_PKF_SECRET_D, &d,
					    SSH_PKF_END);
	  if (status != SSH_CRYPTO_OK)
	    goto fail;

	  fprintf(stderr, "The key parameters are\n"); 
	  str = ssh_mprz_get_str(&n, 16);
	  fprintf(stderr, "n : %s\n\n",str); 
	  ssh_free(str);

	  str = ssh_mprz_get_str(&e, 16);
	  fprintf(stderr, "e : %s\n\n",str); 
	  ssh_free(str);

	  str = ssh_mprz_get_str(&p, 16);
	  fprintf(stderr, "p : %s\n\n",str); 
	  ssh_free(str);

	  str = ssh_mprz_get_str(&q, 16);
	  fprintf(stderr, "q : %s\n\n",str); 
	  ssh_free(str);

	  str = ssh_mprz_get_str(&u, 16);
	  fprintf(stderr, "u : %s\n\n",str); 
	  ssh_free(str);

	  str = ssh_mprz_get_str(&d, 16);
	  fprintf(stderr, "d : %s\n\n",str); 
	  ssh_free(str);

	}
      else if (!strcmp(key_type, "dl-modp"))
	{
	  status = ssh_private_key_get_info(key, 
					    SSH_PKF_GENERATOR_G, &g,
					    SSH_PKF_SECRET_X, &x,
					    SSH_PKF_PUBLIC_Y, &y,
					    SSH_PKF_PRIME_P, &p,
					    SSH_PKF_END);
	  if (status != SSH_CRYPTO_OK)
	    goto fail;

	  fprintf(stderr, "The key parameters are\n"); 
	  str = ssh_mprz_get_str(&g, 16);
	  fprintf(stderr, "g : %s\n\n",str); 
	  ssh_free(str);

	  str = ssh_mprz_get_str(&x, 16);
	  fprintf(stderr, "x : %s\n\n",str); 
	  ssh_free(str);

	  str = ssh_mprz_get_str(&y, 16);
	  fprintf(stderr, "y : %s\n\n",str); 
	  ssh_free(str);

	  str = ssh_mprz_get_str(&p, 16);
	  fprintf(stderr, "p : %s\n\n",str); 
	  ssh_free(str);
	}
      else
	{
	  fprintf(stderr, "Unsupported key type (%s)\n", key_type);
	}
    }

  if (export)
    fprintf(stderr, "Private key exported to %s\n", file_name);
  else
    fprintf(stderr, "Private key successfully imported from %s\n", file_name);

  ssh_mprz_clear(&n);
  ssh_mprz_clear(&e);
  ssh_mprz_clear(&p);
  ssh_mprz_clear(&q);
  ssh_mprz_clear(&u);
  ssh_mprz_clear(&d);
  ssh_mprz_clear(&x);
  ssh_mprz_clear(&y);
  ssh_mprz_clear(&g);
  
  if (buf)
    ssh_free(buf);
  
  if (key)
    ssh_private_key_free(key);
  
  exit(0);

 fail:

  if (export)
    fprintf(stderr, "Private key export to %s failed!!\n", file_name);
  else
    fprintf(stderr, "Private key imported from %s failed!!\n", file_name);

  ssh_mprz_clear(&n);
  ssh_mprz_clear(&e);
  ssh_mprz_clear(&p);
  ssh_mprz_clear(&q);
  ssh_mprz_clear(&u);
  ssh_mprz_clear(&d);
  ssh_mprz_clear(&x);
  ssh_mprz_clear(&y);
  ssh_mprz_clear(&g);
  
  if (buf)
    ssh_free(buf);
  
  if (key)
    ssh_private_key_free(key);
  
  exit(0);


}
