#ifndef T_EAP_H
#define T_EAP_H

#include "sshincludes.h"
#include "ssheap.h"

/* Method independent parameters passed by the method specific test program */
typedef struct SshEapTestParamsRec {

  Boolean client;
  Boolean server;

  /* NUL terminated string */
  unsigned char *local_listener_path;

  /* NUL terminated string */
  unsigned char *radius_url;

  /* Only relevant when running as a server, if set then do not send an 
     EAP identity request. */
  Boolean no_identity;

} SshEapTestParamsStruct, *SshEapTestParams;


/* Callback used by the main test program to request token information */
typedef void (*SshEapTestTokenCB)(SshEap eap,         /* input */
				  SshUInt8 type,      /* input */
				  SshBuffer buf,      /* input */
				  SshEapToken token,  /* output */
				  void *context); 

/* Callback used by the main test program to configure EAP method specific 
   parameters and supported authentication methods to the main test 
   program. */
typedef void (*SshEapTestConfigCB)(SshEap eap, void *context);

/* Callback called by the main program before final destruction. The method 
   specific test program should use this to free any resources it has 
   allocated. */
typedef void (*SshEapTestDestroyCB)(void *context);

/* Run the generic EAP test program from the supplied parameters 
   'params' and token handler. */
int
test_eap_run(const char *program, 
	     SshEapTestParams params,
	     SshEapTestConfigCB config_cb,
 	     SshEapTestTokenCB token_cb,
 	     SshEapTestDestroyCB destroy_cb,
	     void *context); /* context passed to the Token, Config, and 
				Destroy callbacks. */



#endif /* T_EAP_H */
