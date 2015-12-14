/*

  linux_debug.c

  Author: Pekka Riikonen <priikone@ssh.fi>

  Copyright:
          Copyright (c) 2002-2008 SFNT Finland Oy.
  All rights reserved

  Debugging functions for interceptor. These functions are common to
  all Linux 2.x versions.

*/

#include "linux_internal.h"

#define SSH_DEBUG_MODULE "SshInterceptorDebug"







/***************************** Module parameters ****************************/

/* Engine debug string. */
static char *engine_debug = NULL;

MODULE_PARM_DESC(engine_debug, "Engine debug level string.");
module_param(engine_debug, charp, 0444);


/***************************** Debug callbacks ******************************/

/* Called when fatal error occurs. */

void
ssh_kernel_fatal_callback(const char *buf, void *context)
{





  panic("%s\n", buf);
}

/* Called when warning occurs. */

void
ssh_kernel_warning_callback(const char *buf, void *context)
{
  SshInterceptor interceptor = (SshInterceptor) context;

  if (interceptor == NULL)
    {
      ssh_kernel_fatal_callback(buf, context);
      return;
    }

  if (atomic_read(&interceptor->ipm.open) == 0 || interceptor->engine == NULL)
    {
      if (net_ratelimit())
        printk(KERN_CRIT "%s\n", buf);
      return;
    }

  /* Pass the message to the policy manager. */
  local_bh_disable();
  ssh_engine_send_warning(interceptor->engine, buf);
  local_bh_enable();

  return;
}

/* Called when debug message occurs. */

void
ssh_kernel_debug_callback(const char *buf, void *context)
{
  SshInterceptor interceptor = (SshInterceptor) context;
  
  if (interceptor == NULL)
    {
      ssh_kernel_fatal_callback(buf, context);
      return;
    }

  if (atomic_read(&interceptor->ipm.open) == 0 || interceptor->engine == NULL)
    {
      if (net_ratelimit())
        printk(KERN_ERR "%s\n", buf);
      return;
    }

  local_bh_disable();
  ssh_engine_send_debug(interceptor->engine, buf);
  local_bh_enable();

  return;
}


/********************************** Init / Uninit ***************************/

size_t ssh_interceptor_get_debug_level(SshInterceptor interceptor,
				       char *debug_string,
				       size_t debug_string_len)
{
  return ssh_snprintf(debug_string, debug_string_len, "%s",
		      interceptor->debug_level_string);
}

void ssh_interceptor_set_debug_level(SshInterceptor interceptor,
				     char *debug_string)
{
  ssh_snprintf(interceptor->debug_level_string,
	       sizeof(interceptor->debug_level_string),
	       "%s", debug_string);
  
  ssh_debug_set_level_string(interceptor->debug_level_string);
}

void ssh_interceptor_restore_debug_level(SshInterceptor interceptor)
{
  /* Restore debug level. */
  ssh_debug_set_level_string(interceptor->debug_level_string);
}

Boolean
ssh_interceptor_debug_init(SshInterceptor interceptor)
{
  /* Setup debug callbacks. */
  ssh_debug_register_callbacks(ssh_kernel_fatal_callback,
                               ssh_kernel_warning_callback,
                               ssh_kernel_debug_callback,
			       interceptor);
  
  /* Set the default debugging level. */
  if (engine_debug != NULL)
    {
      printk(KERN_ERR "debug string: '%s'\n", engine_debug);
      /*copy engine_debug to interceptor->debug_level_string*/
      ssh_snprintf(interceptor->debug_level_string,
		   sizeof(interceptor->debug_level_string),
		   "%s", engine_debug);
    }
  else
    {
      ssh_snprintf(interceptor->debug_level_string,
		   sizeof(interceptor->debug_level_string),
		   "*=0");
    }

  ssh_debug_set_level_string(interceptor->debug_level_string);









  return TRUE;
}

void
ssh_interceptor_debug_uninit(SshInterceptor interceptor)
{
  /* Uninitialize debug context (free memory) */
  ssh_debug_uninit();





















}







































































































































































































