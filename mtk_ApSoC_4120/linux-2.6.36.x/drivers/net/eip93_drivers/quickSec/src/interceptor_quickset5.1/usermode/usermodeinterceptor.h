/**
    This file is an (internal) header file for the usermode
    interceptor interface implemented in usermodeinterceptor.c.

    File: usermodeinterceptor.h

    @copyright
    Copyright (c) 2002 - 2009 SafeNet Inc, all rights reserved. 

    @author Tatu Ylonen <ylo@ssh.fi>

*/

#include "interceptor.h"
#include "engine.h"
#include "kernel_mutex.h"
#include "kernel_timeouts.h"
#include "sshencode.h"
#include "usermodeforwarder.h"
#include "sshtimeouts.h"
#include "sshpacketstream.h"
#include "sshdevicestream.h"
#include "sshlocalstream.h"
#include "ssheloop.h"
#include "sshgetopt.h"
#include "sshinetencode.h"
#include "sshmutex.h"

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef INTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS
#include "virtual_adapter.h"
#endif /* INTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */







/** Pointer to the interceptor object.  Only one interceptor is supported by
    this implementation. */
extern SshInterceptor ssh_usermode_interceptor;

/** Flags for the usermode interceptor.  These can be used to cause it
    to generate fake errors at random. */
extern SshUInt32 ssh_usermode_interceptor_flags;

#ifdef INTERCEPTOR_PROVIDES_IP_ROUTING
/** Data structure for a route operations that has been sent to the kernel but
    for which no reply has yet been received.  These are kept on a list,
    linked by the 'next' field. */
typedef struct SshInterceptorRouteOpRec
{
  /** Unique identifier for this route operation. */
  SshUInt32 id;

  /** The address for which this route operation was performed. */
  SshIpAddrStruct destination;

  union {
  /** Completion function from the route request. This will be called when
      the reply is received from the kernel. */
    SshInterceptorRouteCompletion completion;
    /** Completion function for the routing table manipulation operation. */
    SshInterceptorRouteSuccessCB success;
  } cb;

  /** Context argument to be passed to the completion function. */
  void *context;

  /** Pointer to next route request in the list. */
  struct SshInterceptorRouteOpRec *next;
} *SshInterceptorRouteOp;
#endif /* INTERCEPTOR_PROVIDES_IP_ROUTING */


#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef INTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS
/** Data structure for a pending virtual adapter operation. */
typedef struct SshInterceptorVirtualAdapterOpRec
{
  /** Pointer to the next pending request. */
  struct SshInterceptorVirtualAdapterOpRec *next;

  /** Is the operation aborted? */
  Boolean aborted;

  /** Is this virtual_adapter_attach operation? */
  Boolean attach;

  /** Unique identifier for this operation.  This is used to match
      usermode forwarder's replies to requests. */
  SshUInt32 id;

  /** Completion callback for the pending operation. */
  SshVirtualAdapterStatusCB status_cb;

  /** Context data for the completion callback. */
  void *context;

  /** Data needed for the attach operation. */
  SshVirtualAdapterPacketCB packet_cb;

  /** Data needed for the detach operation. */
  SshVirtualAdapterDetachCB detach_cb;
  void *adapter_context;

  /** The operation handle of this operation. */
  SshOperationHandle handle;
} *SshInterceptorVirtualAdapterOp;

/** A registry for an existing virtual adapter. */
typedef struct SshInterceptorVirtualAdapterRec
{
  /** Pointer to the next known virtual adapter. */
  struct SshInterceptorVirtualAdapterRec *next;

  /** Adapter's unique id. */
  SshInterceptorIfnum adapter_ifnum;

  /** User-supplied packet callback. */
  SshVirtualAdapterPacketCB packet_cb;

  /** User-supplied data destructor. */
  SshVirtualAdapterDetachCB detach_cb;
  
  void *adapter_context;
} *SshInterceptorVirtualAdapter;
#endif /* INTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */



























/** Data structure for the user-mode interceptor.  This implements a
    fake interceptor for the Engine.  The real interceptor is in the
    kernel, and this communicates with it. */
struct SshInterceptorRec
{
  /** Mutex to protect all concurrent accesses to some of the fields in
      this structure */
  SshMutex mutex;

  /** Machine context argument passsed to ssh_interceptor_open.  This
      should actually be a string naming the device used to talk to the
      kernel. */
  void *machine_context;

  /** Context argument to pass to the callbacks. */
  void *packet_cb_context;
  void *context;

  /** Packet callback. */
  SshInterceptorPacketCB packet_cb;

#ifdef INTERCEPTOR_PROVIDES_IP_ROUTING
  /** Route change callback. */
  SshInterceptorRouteChangeCB route_change_cb;
#endif /* INTERCEPTOR_PROVIDES_IP_ROUTING */

#ifdef INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION
  /** Interface callback. */
  SshInterceptorInterfacesCB interfaces_cb;

  /** Interface information. */
  SshInterceptorInterface *ifs;
  SshUInt32 num_ifs;
#endif /* INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION */

  /** This is set to TRUE when ssh_interceptor_stop is called.  If this is
      set then the interceptor will not make any packet, interface, route
      changed, or debug callbacks to the engine. */
  Boolean stopping;

  /** This is set to TRUE when ssh_interceptor_stop returns TRUE.  This is
      used for sanity checks in ssh_interceptor_close. */
  Boolean stopped;

  /** Number of allocated packets.  This is used for sanity
      checks. Protected by icept mutex. */
  SshUInt32 num_packets;

  /** Number of calls out to the callbacks that haven't returned.
      Route requests are also counted here.  This is used to determine
      when ssh_interceptor_stop can return TRUE. Protected by icept
      mutex. */
  SshUInt32 num_outcalls;

  /** Packet wrapper for talking to the kernel. */
  SshPacketWrapper wrapper;

#ifdef INTERCEPTOR_PROVIDES_IP_ROUTING
  /** Next identifier to use for route requests.  This is incremented by
      one every time this is used.  It is silently assumed that route requests
      do not live long enough for this to wrap. Protected by icept mutex. */
  SshUInt32 next_route_id;

  /** List of route entries for which no reply has yet been
      received. Protected by icept mutex. */
  SshInterceptorRouteOp route_operations;
#endif /* INTERCEPTOR_PROVIDES_IP_ROUTING */

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef INTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS
  /** List of pending virtual adapter operations. Protected by icept mutex. */
  SshInterceptorVirtualAdapterOp virtual_adapter_operations;

  /** The next unique ID for virtual adapter operations. Protected by
      icept mutex. */
  SshUInt32 virtual_adapter_op_id;

  /** Existing virtual adapters. Protected by icept mutex. */
  SshInterceptorVirtualAdapter virtual_adapters;
#endif /* INTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */








  /** Head to (doubly) linked list of allocated packets. If any packet
      is not released by the engine, it will end up here which can then
      be inspected with the debugger. 
      
      Do *not* free this list in ssh_interceptor_close, as that would 
      hide the real memory leak from any memory debuggers (purify, 
      efence et al). Protected by icept mutex. */
  struct SshFakePPRec *packet_head;
};

typedef struct SshInterceptorTimeoutsRec {
  /** Mutex protecting this structure and all timeouts wraps */
  SshMutex mutex;

  /** Timeout list */
  struct SshInterceptorTimeoutWrapRec *timeouts;
} *SshInterceptorTimeouts, SshInterceptorTimeoutsStruct;

/* Bit masks for ssh_usermode_interceptor_flags. */
#define SSH_USERMODE_FAIL_ALLOC       0x01 /** Alloc should fail at random. */
#define SSH_USERMODE_FAIL_PACKET_OP   0x02 /** Packet manipulation functions 
					       should fail at random. */
#define SSH_USERMODE_SHUFFLE_PULLUP 0x04 /** Shuffle at every pullup. */
#define SSH_USERMODE_MANY_NODES       0x08 /** Data is spread over
                                               multiple nodes. */

#ifdef WITH_PURIFY
/** Use single node to make getting data out of leaks easier. Don't
    shuffle at pullups neither, since that erases the original
    allocation point information. */
#define SSH_USERMODE_DEFAULT_FLAGS 0
#else
#define SSH_USERMODE_DEFAULT_FLAGS (SSH_USERMODE_SHUFFLE_PULLUP |       \
                                    SSH_USERMODE_MANY_NODES)
#endif

/** Directly forward a data block to the interceptor, bypassing normal
    encode-wrapping */
Boolean ssh_usermode_interceptor_send(SshInterceptor icept, SshPacketType type,
                                      const unsigned char * data, size_t len);

/** Send a message to the kernel Interceptor, performing normal
    encoding etc. This is semantically (but not implemented directly
    as) calling ssh_packet_wrapper_send_encode on the same arguments
    (sans icept->wrapper). */
Boolean ssh_usermode_interceptor_send_encode(SshInterceptor icept,
                                          SshPacketType type, ...);

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef INTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS
/** Handle for virtual adapter messages. */
void ssh_kernel_receive_virtual_adapter(SshPacketType type,
                                        const unsigned char *data, size_t len);
#endif /* INTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

/** Low-level interceptor init routine. Notice that in the
    normal initialization process the interceptor is the one which
    starts the engine -- here however it is the scaffolding which start
    engine, which open interceptor, at which point only we get the
    interceptor state up. So for timeouts etc. we must actually get
    some initialization *before* Engine is started. */
Boolean ssh_interceptor_init(void *machine_context);

/** Low-level interceptor uninit routine. */
void ssh_interceptor_uninit(void);

/** Allocation of SshInterceptor context. Called by ssh_interceptor_init().
    Can be used separately if ONLY the SshInterceptorPacket functions
    are going to be used. */
SshInterceptor 
ssh_interceptor_alloc(void *machine_context);

/** Counterpart to ssh_interceptor_alloc().
    Is called by ssh_interceptor_uninit(). */
void
ssh_interceptor_free(SshInterceptor interceptor);

#ifdef DEBUG_LIGHT
#define SSH_ASSERT_THREAD() \
        SSH_ASSERT(ssh_threaded_mbox_is_thread(thread_mbox))
#define SSH_ASSERT_ELOOP() \
        SSH_ASSERT(!ssh_threaded_mbox_is_thread(thread_mbox))
#else /* !DEBUG_LIGHT */
#define SSH_ASSERT_THREAD() do {} while (0)
#define SSH_ASSERT_ELOOP() do {} while (0)
#endif /* DEBUG_LIGHT */
