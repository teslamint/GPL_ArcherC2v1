/*

interceptor_tester_ipm.c

Author: Tatu Ylonen <ylo@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
              All rights reserved.

Simple policy manager that is used to drive the interceptor test engine.

*/

#ifdef KERNEL
# undef KERNEL
# undef _KERNEL
#endif

#include "sshincludes.h"
#include "engine.h"
#include "sshencode.h"
#include "interceptor_tester.h"
#include "sshtimeouts.h"
#include "sshpacketstream.h"
#include "sshdevicestream.h"
#include "ssheloop.h"
#include "sshgetopt.h"

#define SSH_DEBUG_MODULE "SshTesterIpm"

typedef struct SshInterceptorTesterRec
{
  /* Packet wrapper for talking to the kernel. */
  SshPacketWrapper wrapper;
} *SshInterceptorTester;

SshInterceptorTester ssh_tester = NULL;

/* Processes a received debug message from the kernel. */

void ssh_kernel_receive_debug(SshInterceptorTester tester,
                              const unsigned char *data, size_t len)
{
  char *str;

  /* Decode the message. */
  if (ssh_decode_array(data, len,
                       SSH_FORMAT_UINT32_STR, &str, NULL,
                       SSH_FORMAT_END) != len)
    {
      SSH_DEBUG_HEXDUMP(0, ("bad debug message received"), data, len);
      return;
    }

  /* Display the debug message here. */
  ssh_debug("%s", str);
  ssh_xfree(str);
}

/* Processes a received warning message from the kernel. */

void ssh_kernel_receive_warning(SshInterceptorTester tester,
                                const unsigned char *data, size_t len)
{
  char *str;

  /* Decode the message. */
  if (ssh_decode_array(data, len,
                       SSH_FORMAT_UINT32_STR, &str, NULL,
                       SSH_FORMAT_END) != len)
    {
      SSH_DEBUG_HEXDUMP(0, ("bad warning message received"), data, len);
      return;
    }

  /* Display the warning message here. */
  ssh_warning("%s", str);
  ssh_xfree(str);
}

/* Process a success message from the engine. */

void ssh_kernel_receive_ok(SshInterceptorTester tester,
                           const unsigned char *data, size_t len)
{
  if (len != 0)
    {
      SSH_DEBUG_HEXDUMP(0, ("bad ok message"), data, len);
      ssh_fatal("bad ok message");
    }

  printf("SUCCESS!\n");

  /* Destroy the packet wrapper for the device.  This also destroys
     the contained device stream and will cause the
     ssh_event_loop_run() to return. */
  ssh_packet_wrapper_destroy(ssh_tester->wrapper);
}

void ssh_kernel_receive_fail(SshInterceptorTester tester,
                             const unsigned char *data, size_t len)
{
  char *str;

  if (ssh_decode_array(data, len,
                       SSH_FORMAT_UINT32_STR, &str, NULL,
                       SSH_FORMAT_END) != len)
    {
      SSH_DEBUG_HEXDUMP(0, ("bad fail message"), data, len);
      ssh_fatal("bad fail message");
    }

  printf("FAILURE: %s\n", str);
  ssh_xfree(str);
  exit(1);
}

/* Process a message received from the kernel.  This dispatches the message
   to the appropriate handler function. */

void ssh_kernel_receive(SshPacketType type,
                        const unsigned char *data, size_t len,
                        void *context)
{
  SshInterceptorTester tester = (SshInterceptorTester)context;

  SSH_DEBUG(2, ("packet type %d from kernel", (int)type));

  /* Dispatch the message to a handler function. */
  switch (type)
    {
    case SSH_ENGINE_IPM_TESTER_OK:
      ssh_kernel_receive_ok(tester, data, len);
      break;

    case SSH_ENGINE_IPM_TESTER_FAIL:
      ssh_kernel_receive_fail(tester, data, len);
      break;

    case SSH_ENGINE_IPM_TESTER_NOTIFY_DEBUG:
      ssh_kernel_receive_debug(tester, data, len);
      break;

    case SSH_ENGINE_IPM_TESTER_NOTIFY_WARNING:
      ssh_kernel_receive_warning(tester, data, len);
      break;

    default:
      break;
    }
}

/* Process EOF from the kernel device.  This should never happen. */

void ssh_kernel_eof(void *context)
{
  ssh_warning("EOF received from kernel module, strage...");
}

/* Callback for handling fatal error messages. */

void fatal_cb(const char *message, void *context)
{
  printf("FATAL: %s\n", message);
  abort();
}

/* Callback for handling warning messages. */

void warning_cb(const char *message, void *context)
{
  printf("Warning: %s\n", message);
}

/* Callback for handling debug messages. */

void debug_cb(const char *message, void *context)
{
  printf("debug: %s\n", message);
}

/* Main program for the user-mode engine. */

int main(int ac, char **av)
{
  int opt;
  char *debuglevel = NULL;
  char *kerneldebuglevel = NULL;
  SshInterceptorTester tester;
  const char *devname;
  SshStream devstream;
  SshUInt32 flags = 0xffffffff;

  /* Process arguments. */
  while ((opt = ssh_getopt(ac, av, "d:D:f:", NULL)) != -1)
    {
      switch (opt)
        {
        case 'd':
          debuglevel = ssh_optarg;
          break;

        case 'D':
          kerneldebuglevel = ssh_optarg;
          break;

        case 'f':
          flags = strtol(ssh_optarg, &ssh_optarg, 0);
          if (*ssh_optarg != '\0')
            ssh_fatal("Bad flags option (should be bit mask 0x...)");
          break;

        default:
          ssh_fatal("Usage: "
                    "interceptor_tester [-d level] [-D level] [-f bitmask]");
        }
    }

  /* Initialize the event loop. */
  ssh_event_loop_initialize();

  /* Set debug level. */
  if (debuglevel)
    ssh_debug_set_level_string(debuglevel);

  devname = "/dev/sshengine-tester";
  devstream = ssh_device_open(devname);
  if (devstream == NULL)
    ssh_fatal("Could not open tester device %s", devname);

  tester = ssh_xcalloc(1, sizeof(*tester));
  ssh_tester = tester;

  /* Wrap the kernel device into a packet stream. */
  tester->wrapper = ssh_packet_wrap(devstream,
                                    ssh_kernel_receive,
                                    ssh_kernel_eof,
                                    NULL,
                                    (void *)tester);
  if (tester->wrapper == NULL)
    ssh_fatal("Could not create packet wrapper");

  /* Register callbacks for the debugging functions. */
  ssh_debug_register_callbacks(fatal_cb,
                               warning_cb,
                               debug_cb,
                               NULL);

  /* Set kernel debug level. */
  if (kerneldebuglevel)
    ssh_packet_wrapper_send_encode(tester->wrapper,
                                   SSH_ENGINE_IPM_TESTER_SET_DEBUG,
                                   SSH_FORMAT_UINT32_STR,
                                     kerneldebuglevel,
                                     strlen(kerneldebuglevel),
                                   SSH_FORMAT_END);

  /* Run the basic test. */
  ssh_packet_wrapper_send_encode(tester->wrapper,
                                 SSH_ENGINE_IPM_TESTER_RUN,
                                 SSH_FORMAT_UINT32,
                                   (SshUInt32) SSH_INTERCEPTOR_TEST_BASIC,
                                 SSH_FORMAT_UINT32, flags,
                                 SSH_FORMAT_END);

  /* Run the event loop, including the engine.  This currently never
     returns. */
  ssh_event_loop_run();

  /* Free the tester object. */
  ssh_xfree(tester);

  /* Uninitialize. */
  ssh_event_loop_uninitialize();
  ssh_util_uninit();
  return 0;
}
