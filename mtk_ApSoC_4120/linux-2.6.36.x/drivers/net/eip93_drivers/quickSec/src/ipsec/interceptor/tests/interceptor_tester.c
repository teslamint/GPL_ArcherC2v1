/*

interceptor_tester.c

Author: Tatu Ylonen

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
              All rights reserved.

This file implements a dummy IPSEC engine that is intended for testing
the interceptor.  This should be used in conjunction with the
interceptor_tester_ipm policy manager.

This performs the following tests:
  - opening and closing the interceptor multiple times; stopping sequence
  - sending packets to the network
  - route interface, completion callback
  - getting interface list and addresses
  - notifications about interface list changing (platform-specific)
  - notifications about routing changes
  - allocating packets, freeing packets, len
  - pullup
  - insert
  - delete
  - copyin, copyout
  - start_iteration, next_iteration
  - basic testing of the policy manager interface
  - stress testing of the policy manager interface
  - testing reliable packets when flooded with unreliable ones
  - multiple opens/closes of the policy manager interface, receiving
    notifications

*/

#include "sshincludes.h"
#include "sshrand.h"
#include "interceptor.h"
#include "engine.h"
#if 0
#include "engine_ipm.h"
#include "engine_version.h"
#endif
#include "kernel_encode.h"
#include "kernel_mutex.h"
#include "interceptor_tester.h"
#include "sshbuffer.h"
#include "sshrand.h"

#ifdef __linux__
extern int32_t random(void);
#endif /* __linux__ */

#define SSH_DEBUG_MODULE "SshTesterEngine"

#define SSH_ENGINE_VERSION "SSH Interceptor Tester 1.0"

const char ssh_engine_version[] = SSH_ENGINE_VERSION;

/* Data structure for the interceptor tester engine. */

struct SshEngineRec
{
  /* Lock for the engine. */
  SshKernelMutex lock;

  /* Function and context for sending packets to the user mode code. */
  SshEngineSendProc send;
  void *machine_context;

  /* Flag indicating that packets should be dropped if the user mode
     code is not connected.  Otherwise packets will be passed through in this
     situation. */
  Boolean drop_if_no_ipm;

  /* Flag indicating whether the user mode connection is currently open. */
  Boolean ipm_open;

  /* Packet interceptor. */
  SshInterceptor interceptor;

  /* Name of the current test. */
  const char *test;
};

/* Formats the message, and tries to send it to the policy manager.  This
   returns FALSE if sending the message fails (e.g., the queue is full).
   Every argument list should start with SSH_FORMAT_UINT32, (SshUInt32) 0,
   SSH_FORMAT_CHAR, type.  The first integer will be set to the length
   of the resulting packet.  This function can be called concurrently. */

Boolean ssh_engine_send(SshEngine engine, Boolean locked,
                        Boolean reliable, ...)
{
  va_list ap;
  unsigned char *ucp;
  size_t len;

  if (!locked)
    ssh_kernel_mutex_lock(engine->lock);
  if (!engine->ipm_open)
    {
      if (!locked)
        ssh_kernel_mutex_unlock(engine->lock);
      return FALSE;
    }
  if (!locked)
    ssh_kernel_mutex_unlock(engine->lock);

  /* WARNING: this function is called from ssh_debug callback, which
     means that no debug functions can be called here or we'll end up
     with infinite recursion. */

  /* Construct the final packet to send to ipm. */
  va_start(ap, reliable);
  len = ssh_encode_array_alloc_va(&ucp, ap);
  va_end(ap);
  SSH_ASSERT(len >= 5); /* must have at least len+type */

  /* Update the length of the packet. */
  SSH_PUT_32BIT(ucp, len - 4);

  /* Send and/or queue the packet to the ipm.  This will free the buffer. */
  return (*engine->send)(ucp, len, reliable, engine->machine_context);
}

/* Send a debugging message to the policy manager. */
void
ssh_engine_send_debug(SshEngine engine, const char *message)
{
  ssh_engine_send(engine, FALSE, FALSE,
                  SSH_FORMAT_UINT32, (SshUInt32) 0, /* reserved for length */

                  SSH_FORMAT_CHAR,
                  (unsigned int) SSH_ENGINE_IPM_TESTER_NOTIFY_DEBUG,

                  SSH_FORMAT_UINT32_STR, message, strlen(message),
                  SSH_FORMAT_END);
}

/* Send a warning message to the policy manager. */
void
ssh_engine_send_warning(SshEngine engine, const char *message)
{
  ssh_engine_send(engine, FALSE, FALSE,
                  SSH_FORMAT_UINT32, (SshUInt32) 0, /* reserved for length */
                  SSH_FORMAT_CHAR,
                  (unsigned int) SSH_ENGINE_IPM_TESTER_NOTIFY_WARNING,
                  SSH_FORMAT_UINT32_STR, message, strlen(message),
                  SSH_FORMAT_END);
}


/* Callback function called by the real interceptor whenever a packet
   is received.  This passes the packet to the user mode
   interceptor. */

void ssh_engine_packet_callback(SshInterceptorPacket pp, void *context)
{
  SshEngine engine = (SshEngine)context;
  size_t mediahdr_len;

  /* Determine media header length. */
  if (pp->protocol == SSH_PROTOCOL_ETHERNET)
    mediahdr_len = SSH_ETHERH_HDRLEN;
  else
    if (pp->protocol == SSH_PROTOCOL_FDDI ||
        pp->protocol == SSH_PROTOCOL_TOKENRING)
      mediahdr_len = 22; 



    else
      mediahdr_len = 0;

  /* Send it through. */
  ssh_interceptor_send(engine->interceptor, pp, mediahdr_len);
}


/* This function is called whenever the interface list changes. */

void ssh_engine_interfaces_callback(SshUInt32 num_interfaces,
                                    SshInterceptorInterface *ifs,
                                    void *context)
{
  SSH_DEBUG(1, ("interfaces callback"));
}

/* Function that is called whenever routing information changes.  There
   is no guarantee that this ever gets called. */

void ssh_engine_route_change_callback(void *context)
{
  SSH_DEBUG(1, ("route change callback"));
}

/* Creates the engine object.  Among other things, this opens the
   interceptor, initializes filters to default values, and arranges to send
   messages to the policy manager using the send procedure.  The send
   procedure will not be called until from the bottom of the event loop.
   The `machine_context' argument is passed to the interceptor and the
   `send' callback, but is not used otherwise.  This function can be
   called concurrently for different machine contexts, but not otherwise.
   The first packet and interface callbacks may arrive before this has
   returned. */

SshEngine ssh_engine_start(SshEngineSendProc send,
                           void *machine_context,
                           SshUInt32 flags)
{
  SshEngine engine;

  engine = ssh_calloc(1, sizeof(*engine));
  if (engine == NULL)
    {
      SSH_DEBUG(1, ("allocating the engine object failed"));
      goto fail;
    }

  /* Transform data pointers are already all zero (assumed to equal NULL). */
  /* Fragment magic data initialized to zero. */
  engine->lock = ssh_kernel_mutex_alloc();
  engine->send = send;
  engine->machine_context = machine_context;
  engine->drop_if_no_ipm = (flags & SSH_ENGINE_DROP_IF_NO_IPM) != 0;
  engine->ipm_open = FALSE;
  engine->interceptor = NULL;

  /* Create the interceptor. */
  if (!ssh_interceptor_create(machine_context, &engine->interceptor))
    {
      SSH_DEBUG(1, ("creating the interceptor failed"));
      goto fail;
    }

  /* Open the interceptor. */
  if (!ssh_interceptor_open(engine->interceptor,
			    ssh_engine_packet_callback,
			    ssh_engine_interfaces_callback,
			    ssh_engine_route_change_callback,
			    (void *)engine))                            
    {
      SSH_DEBUG(1, ("opening the interceptor failed"));
      goto fail;
    }

  SSH_DEBUG(1, ("SSH tester engine started"));
  return engine;

 fail:
  if (engine)
    {
      if (engine->interceptor)
	ssh_interceptor_stop(engine->interceptor);
      ssh_kernel_mutex_free(engine->lock);
      ssh_free(engine);
    }
  return NULL;

}

/* Stops the engine, closes the interceptor, and destroys the
   engine object.  This does not notify IPM interface of the close;
   that must be done by the caller before calling this.  This returns
   TRUE if the engine was successfully stopped (and the object freed),
   and FALSE if the engine cannot yet be freed because there are
   threads inside the engine or uncancellable callbacks expected to
   arrive.  When this returns FALSE, the engine has started stopping,
   and this should be called again after a while.  This function can
   be called concurrently with packet/interface callbacks or timeouts
   for this engine, or any functions for other engines.*/

Boolean ssh_engine_stop(SshEngine engine)
{
  /* Stop the interceptor.  This means that no more new callbacks will
     arrive. */
  if (!ssh_interceptor_stop(engine->interceptor))
    return FALSE;

  /* Close the packet interceptor. */
  ssh_interceptor_close(engine->interceptor);

  /* Free the engine data structures. */
  ssh_kernel_mutex_free(engine->lock);
  memset(engine, 'F', sizeof(*engine));
  ssh_free(engine);
  return TRUE;
}

/* The machine-specific main program should call this when the policy
   manager has opened the connection to the engine.  This also
   sends the version packet to the policy manager.  This function can
   be called concurrently with packet/interface callbacks or timeouts. */

void ssh_engine_notify_ipm_open(SshEngine engine)
{
  SSH_DEBUG(1, ("User level module opened connection."));

  /* Update state information about the policy manager connection. */
  ssh_kernel_mutex_lock(engine->lock);
  SSH_ASSERT(!engine->ipm_open);
  engine->ipm_open = TRUE;
  ssh_kernel_mutex_unlock(engine->lock);
}

/* This function is called whenever the policy manager closes the
   connection to the engine.  This is also called when the engine is
   stopped.  This function can be called concurrently with
   packet/interface callbacks or timeouts. */

void ssh_engine_notify_ipm_close(SshEngine engine)
{
  SSH_DEBUG(1, ("User level module closed connection."));

  /* Lock the engine. */
  ssh_kernel_mutex_lock(engine->lock);

  /* Mark the policy interface not open. */
  engine->ipm_open = FALSE;

  /* Unlock the engine. */
  ssh_kernel_mutex_unlock(engine->lock);
}




/* Report success from a test. */

void ssh_engine_test_ok(SshEngine engine)
{
  SSH_DEBUG(0, ("test '%s' successful", engine->test));
  ssh_engine_send(engine, FALSE, TRUE,
                  SSH_FORMAT_UINT32, (SshUInt32) 0,
                  SSH_FORMAT_CHAR, (unsigned int) SSH_ENGINE_IPM_TESTER_OK,
                  SSH_FORMAT_END);
  engine->test = NULL;
}

/* Report failure from a test. */

void ssh_engine_test_fail(SshEngine engine, const char *fmt, ...)
{
  va_list va;
  char buf[1024];

  va_start(va, fmt);
  ssh_vsnprintf(buf, sizeof(buf), fmt, va);
  va_end(va);

  SSH_DEBUG(0, ("test '%s' failed", engine->test));
  ssh_engine_send(engine, FALSE, TRUE,
                  SSH_FORMAT_UINT32, (SshUInt32) 0,
                  SSH_FORMAT_CHAR, (unsigned int) SSH_ENGINE_IPM_TESTER_FAIL,
                  SSH_FORMAT_UINT32_STR, buf, strlen(buf),
                  SSH_FORMAT_END);
  engine->test = NULL;
}

/* Run very basic tests.  This just checks that every function sort of
   works. */

void ssh_engine_test_basic(SshEngine engine, SshUInt32 flags)
{
  SshUInt32 pass, packetflags, proto, ifnum_in, ifnum_out, sum, offset;
  SshUInt32 i;
  size_t seglen, prevseglen, len, iterlen;
  unsigned char *seg, *prevseg;
  SshInterceptorPacket pp;

  engine->test = "basic";

  SSH_DEBUG(0, ("testing basic packet processing functions"));
  for (pass = 0; pass < 1000; pass++)
    {
      if (pass % 100 == 0)
        SSH_DEBUG(0, ("pass=%d", (int)pass));

      /* Compute packet length.  We want to test all small values, and
         others at random. */
      if (ssh_rand() % 2 == 0)
        packetflags = SSH_PACKET_FROMADAPTER;
      else
        packetflags = SSH_PACKET_FROMPROTOCOL;
      if (pass < 300)
        len = pass;
      else
        len = ssh_rand() % 100000;
      ifnum_in = ssh_rand() % ((SshInterceptorIfnum) 0xffffffff);
      ifnum_out = ssh_rand() % ((SshInterceptorIfnum) 0xffffffff);
      proto = SSH_PROTOCOL_IP4;
      SSH_DEBUG(1, ("packetflags 0x%lx, len %ld, proto %d",
                    (long)packetflags, (long)len, (int)proto));
      pp = ssh_interceptor_packet_alloc(engine->interceptor,
                                        packetflags, proto, 
					ifnum_in, ifnum_out, len);
      if (pp == NULL)
        {
          ssh_engine_test_fail(engine, "packet_alloc returned NULL");
          return;
        }
      if ((pp->flags &
           (0xffffff00|SSH_PACKET_FROMPROTOCOL|SSH_PACKET_FROMADAPTER)) !=
          packetflags)
        {
          ssh_engine_test_fail(engine, "packet_alloc flags not properly set");
          ssh_interceptor_packet_free(pp);
          return;
        }
      /* Add all flags reserved to the engine so that the interceptor cannot
         use them for anything. */
      pp->flags |= 0xffffff00;

      /* Check protocol and ifnum. */
      if (pp->protocol != proto)
        {
          ssh_engine_test_fail(engine, "packet_alloc proto not properly set");
          ssh_interceptor_packet_free(pp);
          return;
        }
      if (pp->ifnum_in != ifnum_in)
        {
          ssh_engine_test_fail(engine, 
			       "packet_alloc ifnum_in not properly set");
          ssh_interceptor_packet_free(pp);
          return;
        }
      if (pp->ifnum_out != ifnum_out)
        {
          ssh_engine_test_fail(engine, 
			       "packet_alloc ifnum_out not properly set");
          ssh_interceptor_packet_free(pp);
          return;
        }

      /* Check that packet length is correctly returned. */
      if (ssh_interceptor_packet_len(pp) != len)
        {
          ssh_engine_test_fail(engine, "packet_alloc returned wrong len %ld "
                               "should have been %ld",
                               (long)ssh_interceptor_packet_len(pp),
                               (long)len);
          ssh_interceptor_packet_free(pp);
          return;
        }

      if (flags & SSH_INTERCEPTOR_TEST_BASIC_ITERATE)
        {
          SSH_DEBUG(1, ("iterating"));

          for (i = 0; i < 10; i++)
            {
              offset = ssh_rand() % (len + 1);
              iterlen = ssh_rand() % (len - offset + 1);
              SSH_ASSERT(offset + iterlen <= len);
              sum = 0;
              prevseg = NULL;
              prevseglen = 0;
              ssh_interceptor_packet_reset_iteration(pp, offset, iterlen);
              while (ssh_interceptor_packet_next_iteration(pp, &seg, &seglen))
                {
                  if (prevseg && prevseglen != 0)
                    if (prevseg[0] != (prevseglen & 0xff))
                      {
                        ssh_engine_test_fail(engine,
                                             "iter pointer not preserved");
                        ssh_interceptor_packet_free(pp);

                        return;
                      }

                  sum += seglen;
                  memset(seg, seglen & 0xff, seglen);
                  prevseg = seg, prevseglen = seglen;
                }
              if (seg != NULL)
                {
                  ssh_engine_test_fail(engine, "next iteration fails");
                  return;
                }
              if (sum != iterlen)
                {
                  ssh_engine_test_fail(engine, "iteration test fails");
                  ssh_interceptor_packet_free(pp);
                  return;
                }
            }
        }

      if (flags & SSH_INTERCEPTOR_TEST_BASIC_PREPEND)
        {
          SSH_DEBUG(1, ("inserting (prepend)"));

          seg = ssh_interceptor_packet_insert(pp, 0, 80);
          if (seg == NULL)
            {
              ssh_engine_test_fail(engine, "insert (prepend) 80 failed");
              return;
            }
          memset(seg, 'I', 80);
          len += 80;

          for (i = 0; i < 10; i++)
            {
              seglen = ssh_rand() % (80 + 1);
              SSH_ASSERT(seglen <= 80);
              seg = ssh_interceptor_packet_insert(pp, 0, seglen);
              if (seg == NULL)
                {
                  ssh_engine_test_fail(engine, "insert (prepend) failed");
                  return;
                }
              memset(seg, 'I', seglen);
              len += seglen;
            }
          if (len != ssh_interceptor_packet_len(pp))
            {
              ssh_engine_test_fail(engine, "len mismatch after insert");
              ssh_interceptor_packet_free(pp);
              return;
            }
        }

      if (flags & SSH_INTERCEPTOR_TEST_BASIC_PULLUP)
        {
          SSH_DEBUG(1, ("pullup"));

          for (i = 0; i < 10; i++)
            {
              seglen = ssh_rand() % (80 + 1);
              SSH_ASSERT(seglen <= 80);
              if (seglen > len)
                seglen = len;
              seg = ssh_interceptor_packet_pullup(pp, seglen);
              if (seg == NULL)
                {
                  ssh_engine_test_fail(engine, "pullup failed");
                  return;
                }
              if (flags & SSH_INTERCEPTOR_TEST_BASIC_PREPEND)
                for (offset = 0; offset < seglen; offset++)
                  if (seg[offset] != 'I')
                    {
                      ssh_engine_test_fail(engine, "pullup compare failed");
                      ssh_interceptor_packet_free(pp);
                      return;
                    }
            }
          if (len != ssh_interceptor_packet_len(pp))
            {
              ssh_engine_test_fail(engine, "len mismatch after pullup");
              ssh_interceptor_packet_free(pp);
              return;
            }
        }

      if (flags & SSH_INTERCEPTOR_TEST_BASIC_INSERT)
        {
          SSH_DEBUG(1, ("random inserts"));

          for (i = 0; i < 10; i++)
            {
              offset = ssh_rand() % (len + 1);
              seglen = ssh_rand() % (80 + 1);
              seg = ssh_interceptor_packet_insert(pp, offset, seglen);
              if (seg == NULL)
                {
                  ssh_engine_test_fail(engine, "insert failed");
                  return;
                }
              memset(seg, 'i', seglen);
              len += seglen;
            }
          if (len != ssh_interceptor_packet_len(pp))
            {
              ssh_engine_test_fail(engine, "len mismatch after pullup");
              ssh_interceptor_packet_free(pp);
              return;
            }
        }

      if (flags & SSH_INTERCEPTOR_TEST_BASIC_DELETE)
        {
          SSH_DEBUG(1, ("random deletes"));

          for (i = 0; i < 10; i++)
            {
              offset = ssh_rand() % (len + 1);
              seglen = ssh_rand() % (len - offset + 1);
              if (!ssh_interceptor_packet_delete(pp, offset, seglen))
                {
                  ssh_engine_test_fail(engine, "packet_delete failed");
                  return;
                }
              len -= seglen;
            }
          if (len != ssh_interceptor_packet_len(pp))
            {
              ssh_engine_test_fail(engine, "len mismatch after delete");
              ssh_interceptor_packet_free(pp);
              return;
            }
        }

      if (flags & SSH_INTERCEPTOR_TEST_BASIC_ITERATE)
        {
          SSH_DEBUG(1, ("iterating again"));

          /* Again check that all iterations return correct total length. */
          for (i = 0; i < 10; i++)
            {
              offset = ssh_rand() % (len + 1);
              iterlen = ssh_rand() % (len - offset + 1);
              SSH_ASSERT(offset + iterlen <= len);
              sum = 0;
              prevseg = NULL;
              prevseglen = 0;
              ssh_interceptor_packet_reset_iteration(pp, offset, iterlen);
              while (ssh_interceptor_packet_next_iteration(pp, &seg, &seglen))
                {
                  if (prevseg && prevseglen != 0)
                    if (prevseg[0] != (prevseglen & 0xff))
                      {
                        ssh_engine_test_fail(engine,
                                             "iter pointer not preserved");
                        ssh_interceptor_packet_free(pp);
                        return;
                      }

                  sum += seglen;
                  memset(seg, seglen & 0xff, seglen);
                  prevseg = seg, prevseglen = seglen;
                }
              if (seg != NULL)
                {
                  ssh_engine_test_fail(engine, "next iteration fails");
                  return;
                }
              if (sum != iterlen)
                {
                  ssh_engine_test_fail(engine, "iteration (again) test fails");
                  ssh_interceptor_packet_free(pp);
                  return;
                }
            }
        }

      SSH_DEBUG(1, ("freeing"));

      ssh_interceptor_packet_free(pp);
    }

  ssh_engine_test_ok(engine);
}

/* Processes a set debug level message from the policy manager.  This function
   can be called concurrently. */

void ssh_engine_from_ipm_set_debug(SshEngine engine,
                                   const unsigned char *data, size_t len)
{
  char *s;

  /* Decode the packet. */
  if (ssh_decode_array(data, len,
                              SSH_FORMAT_UINT32_STR, &s, NULL,
                              SSH_FORMAT_END) != len)
    {
      SSH_DEBUG_HEXDUMP(0, ("Bad set debug from policy manager"),
                        data, len);
      return;
    }

  /* Set debug level according to the stringl. */



  ssh_debug_set_level_string(s);
  SSH_DEBUG(1, ("Engine debug level set to %s", s));
  ssh_free(s);
}

/* Processes a run test message from the tester policy manager. */

void ssh_engine_from_ipm_run(SshEngine engine,
                             const unsigned char *data, size_t len)
{
  SshUInt32 test_number, flags;

  if (ssh_decode_array(data, len,
                              SSH_FORMAT_UINT32, &test_number,
                              SSH_FORMAT_UINT32, &flags,
                              SSH_FORMAT_END) != len)
    {
      SSH_DEBUG_HEXDUMP(0, ("bad run packet"), data, len);
      return;
    }

  switch (test_number)
    {
    case SSH_INTERCEPTOR_TEST_BASIC:
      ssh_engine_test_basic(engine, flags);
      break;

    default:
      ssh_warning("unknown test %ld", (long)test_number);
      ssh_engine_test_fail(engine, "unknown test %ld", (long)test_number);
      break;
    }
}

/* This function should be called by the machine-dependent main
   program whenever a packet for this engine is received from
   the policy manager.  The data should not contain the 32-bit length
   or the type (they have already been processed at this stage, to
   check for possible machine-specific packets).  The `data' argument
   remains valid until this function returns; it should not be freed
   by this function.  This function can be called concurrently. */

void ssh_engine_packet_from_ipm(SshEngine engine,
                                SshUInt32 type,
                                const unsigned char *data, size_t len)
{
  switch (type)
    {
    case SSH_ENGINE_IPM_TESTER_RUN:
      ssh_engine_from_ipm_run(engine, data, len);
      break;

    case SSH_ENGINE_IPM_TESTER_SET_DEBUG:
      ssh_engine_from_ipm_set_debug(engine, data, len);
      break;

    default:
      ssh_warning("ssh_engine_packet_from_ipm: unexpected packet %d in "
                  "kernel; probably wrong policy manager", len);
      break;
    }
}


/* Suffix to add to the name of the device name used for communicating with
   the kernel module in systems that have such a concept.  This is ignored
   on other systems. */
const char ssh_device_suffix[] = "-tester";
