/*

t-simple_externalkey.c

Author: Vesa Suontama <vsuontam@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
                   All rights reserved

Created: Tue April 5 11:50 2000 vsuontam

*/

/* This a very simple example of how the externalkey system can be 
   used to get handles to private keys. The test program signs data 
   when it has obtained a handle to a key. It also fetcehs a certificate
   and prints the subject name from it. 

   All the operations are asynchronic, so the execution of the program
   may be hard to understand. The execution of the program is explained 
   below. 
   
   The actual execution starts at the bottom from "main" function,
   where a call to test_ek_add is made that allocates the
   externalkey system and adds the provider.

   When the externalkey has has been allocated a provider is added to
   the system.  Each provider is identified with a string
   e.g. "smartcard".
  
   Then we enable a provider and register two callbacks. Authentication 
   callback, that is called if a PIN code is needed, and a notify callback, 
   that is called when something "intresting" happens. The notify callback
   is called, for example, when an installed provider find that it has some
   keys. 

   The interesting exection of this code continues, when the externalkey 
   system calls the notification callback "ssh_externalkey_notify_cb". 
   In notify callback, each key and certificate is identified with a string 
   called keypath. The test program uses the keypath to retrieve a handle
   to a private key asynchronously. The certificate is also fetched 
   asynchronously. These operations are started in 
   "ssh_get_authentication_key_and_certificate". When the asynchronous 
   fetching operations are done, the externalkey system calls result callbacks
   ssh_get_privatekey_callback and ssh_get_certificate_callback. 

   In ssh_get_privatekey_callback, we do a signature asynchronosly, if we
   were able to get the key. The signature operation calls "ssh_sign_cb",
   when the operation is done, either succesfully or not. 

   In ssh_get_certificate_callback we try to read a subject name from a 
   certificate if the retrieving of the certificate was succesfull. */

#include "sshincludes.h"
#include "sshgetopt.h"
#include "sshexternalkey.h"
#include "ssheloop.h"
#include "sshcrypt.h"
#include "x509.h"
#include "sshtimeouts.h"

#define SSH_DEBUG_MODULE "ExternalKeyTest"

#define SIGN_TEXT "This string will be signed."
#define SIGN_TEXT_LEN (strlen(SIGN_TEXT) + 1)


/* Some global arguments for the test. */
/* Externalkey used in this test. */
static SshExternalKey ssh_global_externalkey;

/* Default debug string. */
static char *debug_level_string = "*=4,SshEK*=9,ExternalKeyTest=10";

/* Default externalkey provider. Change with "-t" option. */
static char *provider_type = "smartcard";

/* Initialization info for the provider. Change with "-i" option. */
static char *initialization_string = "";


/* Usage. */
static void print_usage(void)
{
  printf("Parameters:\n"
         "-t <type> The externalkey provider type.\n"
         "\t(e.g 'smartcard')\n"
         "-i <init_str> Itialization string for the externalkey provider.\n"
         "\t(e.g 'reader(setec, /dev/tty00), card(setec)'"
         "-d Set the debug level string.\n");

}

/* Simple argumetn parsing. */
static void parse_arguments(int argc, char **argv)
{
  char opt;

  while ((opt = ssh_getopt(argc, argv, "t:i:d:h", NULL)) != EOF)
    {
      switch (opt)
        {
        case 't':
          provider_type = ssh_optarg;
          break;
        case 'i':
          initialization_string = ssh_optarg;
          break;
        case 'd':
          debug_level_string = ssh_optarg;
          break;

        case 'h':
        case '?':
        default:
          /* the Usage. */
          print_usage();
          exit(1);
        }
    }
}

/* Is called by the event loop to uninitialize the externalkey. 
   We can not do this directly in ssh_end_test, beacause we might be
   in a callback from externalkey. */
void ssh_end_test_cb(void *context)
{
  ssh_ek_free(ssh_global_externalkey, NULL_FNPTR, NULL); 
}



/* Is called to increment a reference count. When count reaches 2, the 
   EK will be uninitialized. */
static void ssh_end_test(void)
{
  static int count = 0;
  /* We end the test when count reaches 2 */
  count++;
  if (count == 2)
    ssh_xregister_timeout(0, 0, ssh_end_test_cb, NULL);
}

void ssh_sign_cb(SshCryptoStatus status,
             const unsigned char *signature_buffer,
             size_t signature_buffer_len,
             void *context)
{
  SshPrivateKey key = (SshPrivateKey)context;
  if (status == SSH_CRYPTO_OK)
    {
      /* OK, the signature was computed succesfully and the 
         signature is in the signature_buffer and its length is 
         in signature_buffer_len. */
      printf("The test data was signed OK. \n");
    }
  else
    {
      /* There was some error in generating the signature. */
      printf("There were an error generating the signature.\n");
    }
  /* Test if we can quit the test. */
  ssh_private_key_free(key);
  ssh_end_test();
}

/* This callback is called by the externalkey system, when a handle to 
   the private key is obtained by some of the installed providers. */
void ssh_get_privatekey_callback(SshEkStatus status, 
                                 SshPrivateKey key, 
                                 void *context)
{
  if (status == SSH_EK_OK)
    {

      /* We got the key. Now we can do signatures...*/
      ssh_private_key_sign_async(key, SIGN_TEXT,
                                 SIGN_TEXT_LEN, ssh_sign_cb, key);
      
    }
  else
    {
      /* There was an some error obtaining the handle to the key. */
      printf("Could not get the private key from the provider.\n");
      ssh_end_test();
    }
}


/* This callback is called by the externalkey system, when the certificate 
   is obtained by some of the installed providers. */
void ssh_get_certificate_callback(SshEkStatus status,
                                  const unsigned char *cert_return,
                                  size_t cert_return_length,
                                  void *context)
{
  if (status == SSH_EK_OK)
    {
      SshX509Certificate cert;
      char *subject_name;
      /* OK we got the certificate. Print the subject name of the 
         certificate. */

      /* Allocate a certificate object. */
      cert = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);

      /* Decode the certificate. */
      ssh_x509_cert_decode(cert_return, cert_return_length, cert);

      /* Read the subject name from the certificate. */
      ssh_x509_cert_get_subject_name(cert, &subject_name);

      /* Print the subject name. */
      printf("The subject name of the certificate is %s\n", subject_name);

      /* Free the certificate. */
      ssh_x509_cert_free(cert);

      /* Free the subject name. */
      ssh_xfree(subject_name);
    }
  else
    {
      /* Some error occured fething the certificate. */
      printf("Could not fetch the certifiate.\n");
    }
  /* Check if we can end this test now. */
  ssh_end_test();
}



/* This fetches the key and certificate that are bound to a keypath. 
   Externalkey system calls to the ssh_get_privatekey_callback and 
   ssh_get_certificate_callback, when it has processed the requests. */
void ssh_get_authentication_key_and_certificate(const char *keypath)
{
  /* Get a handle to the private key. */
  ssh_ek_get_private_key(ssh_global_externalkey, keypath, 
    ssh_get_privatekey_callback, NULL);
  
  /* Get the first certificate. */
  ssh_ek_get_certificate(ssh_global_externalkey, keypath, 0,
    ssh_get_certificate_callback, NULL);
}



/* This callback is called, if the installed externalkey providers 
   have keys and certificates. */
void ssh_externalkey_notify_cb(SshEkEvent event,
                               const char *keypath,                            
                               const char *label,
                               SshEkUsageFlags flags,
                               void *context)
{

  if (event == SSH_EK_EVENT_KEY_AVAILABLE)
    {
      /* This event means we have an key available from the provider. */
      if (flags & SSH_EK_USAGE_AUTHENTICATE)
        {
          /* OK... We have an key and certificate that can be used 
             for authentication. */
          ssh_get_authentication_key_and_certificate(keypath);
        }
    }

  if (event == SSH_EK_EVENT_KEY_UNAVAILABLE)
    {
      /* This event means that a key is temporarely unavailable. */

    }

  return;

}

/* Authentication callback is called by the externalkey system if 
   a PIN code is needed for some operation. In a real world, some 
   dialog should be displayed to the user. */ 
SshOperationHandle ssh_externalkey_authentication_cb(const char *keypath,
                                                     const char *label,
                                                     SshUInt32 try_number,
                                                     SshEkAuthenticationStatus
                                                     authentication_status,
                                                     SshEkAuthenticationReplyCB
                                                     reply_cb,
                                                     void *reply_context,
                                                     void *context)
{
  unsigned char pin_buffer[100];
  int i = 0;

  printf("(Warning: Your PIN will be visible)\n"
    "PIN CODE for %s please:", label);

  scanf("%s", pin_buffer);

  i = strlen(pin_buffer);
  reply_cb(pin_buffer, i, reply_context);
  return NULL;
}


/* Allocate externalkey. aIn this function we also add a default
   provider and enable it. */
static void test_ek_add(void)
{
  SshExternalKey externalkey;

  /* Allocate the externalkey. */
  externalkey = ssh_ek_allocate();

  /* Store the externalkey object to the global variable. 
     Using global variables is dummy, but in this example program, 
     it may be ok. */
  ssh_global_externalkey = externalkey;
  
  /* Register notify callback. */
  ssh_ek_register_notify(externalkey, ssh_externalkey_notify_cb, NULL);

  /* Register authentication callback. */
  ssh_ek_register_authentication_callback(externalkey,
                                          ssh_externalkey_authentication_cb,
                                          NULL);


  /* Add the default provider to externalkey. 
     We decide here what are the providers we want to use. For this
     example, we use the provider in provider_type variable. */
  if (ssh_ek_add_provider(externalkey, provider_type,
                          initialization_string, NULL, 0, NULL) != SSH_EK_OK)
    {
      ssh_warning("Could not add '%s' provider with '%s' in initialization "
                  "string.", provider_type, initialization_string);
      exit(1);
    }
    
  /* And we are done initializing. Externalkey system will call the notify 
     callback to notify us, provider has keys available. */
}





/* The main. */
int main(int argc, char **argv)
{
  /* Parse arguments. */
  parse_arguments(argc, argv);

  /* Initialize the event loop. */
  ssh_event_loop_initialize();

  /* Allocate and initialize the externalkey interface. */
  test_ek_add();

  /* Start the event loop. This wont return, unless somebody 
     calls ssh_event_loop_abort(). */
  ssh_event_loop_run();

  /* Uninitialize the event loop. */
  ssh_event_loop_uninitialize();

  return 0;
}


