/*
  File: appgw_sip_ports.c

  Copyright:
  	Copyright (c) 2003 SFNT Finland Oy.
	All rights reserved.

  Description:
        Open ports for RTP traffic
*/

#include "sshincludes.h"
#include "sshinet.h"
#include "sshfsm.h"
#include "appgw_api.h"
#include "appgw_sip.h"

#ifdef SSHDIST_IPSEC_FIREWALL

#define SSH_DEBUG_MODULE "SshAppgwSIP"

struct SipOpenPortRec
{
  SshAppgwContext instance;
  SshUInt16 baseport;
  SshUInt16 dstport;
  SshUInt16 nports;
  SshUInt16 currport;

  SshUInt32 last_open_handle;

  Boolean failed;

  SshAppgwSipPortCB callback;
  void *callback_context;

  SshOperationHandle master_op;
  SshOperationHandle op;

  SshFSMThreadStruct thread;

  Boolean initiator_inside;
};
typedef struct SipOpenPortRec *SipOpenPort;

static SSH_FSM_STEP(sip_port_open);
static SSH_FSM_STEP(sip_port_open_done);

static void
sip_port_open_callback(SshAppgwContext instance,
		       Boolean success,
		       const SshIpAddr new_dst_ip,
		       SshUInt16 new_dst_port,
		       SshUInt32 open_port_handle,
		       void *context)
{
  SipOpenPort op = context;

  op->op = NULL;
  if (success)
    {
      op->currport += 1;
      op->last_open_handle = open_port_handle;
    }
  else
    {
      op->failed = TRUE;
      ssh_fsm_set_next(&op->thread, sip_port_open_done);
    }
  SSH_FSM_CONTINUE_AFTER_CALLBACK(&op->thread);
}

static SSH_FSM_STEP(sip_port_open)
{
  SshUInt32 flags;
  SshAppgwParamsStruct params;
  SipOpenPort op = thread_context;
  SshAppgwSip alg = ssh_fsm_get_gdata(thread);

  if (op->last_open_handle)
    {
      /* first time we hit here, currport has already been handled. */
      int index = op->baseport - alg->baseport + op->currport - 1;

      alg->portmap_handles[index] = op->last_open_handle;
      SSH_DEBUG(SSH_D_MIDOK,
		("Registering open port handle %d at index %d for port %d",
		 (int) op->last_open_handle,
		 index,
		 op->baseport + op->currport - 1));
    }
  if (op->currport == op->nports)
    {
      SSH_FSM_SET_NEXT(sip_port_open_done);
      return SSH_FSM_CONTINUE;
    }

  /* Set the public port number here */
  memset(&params, 0, sizeof(params));
  params.forced_port = op->baseport + op->currport;

  SSH_DEBUG(SSH_D_MIDOK,
	    ("OPEN; forced_port=%d, dstport=%d",
	     params.forced_port,
	     (op->dstport + op->currport)));

  SSH_FSM_SET_NEXT(sip_port_open);
  SSH_FSM_ASYNC_CALL({
    flags  = SSH_APPGW_OPEN_FORCED|SSH_APPGW_OPEN_MULTIPLE;
    if (!op->initiator_inside)
      flags |= SSH_APPGW_OPEN_FROM_INITIATOR;

    op->op =
      ssh_appgw_open_port(op->instance,
			  &params,
			  0, (SshUInt16)(op->dstport + op->currport),
			  flags,
			  sip_port_open_callback,
			  op);
  });
}

static SSH_FSM_STEP(sip_port_open_done)
{
  SipOpenPort op = thread_context;

  if (op->failed)
    {
      (*op->callback)(0, 0, op->callback_context);
    }
  else
    {
      (*op->callback)(op->baseport, op->nports, op->callback_context);
    }
  ssh_operation_unregister(op->master_op);
  return SSH_FSM_FINISH;
}

static void
alg_sip_create_destroy(SshFSM fsm, void *context)
{
  SipOpenPort op = context;

  ssh_free(op);
}

static void
alg_sip_create_abort(void *context)
{
  SipOpenPort op = context;

  if (op->op)
    ssh_operation_abort(op->op);
  ssh_operation_unregister(op->master_op);

  /* then kill the thread, it will not be woken as it does not
     receive callbacks any longer. */
  ssh_fsm_kill_thread(&op->thread);
  ssh_free(op);
}

/* Open nports starting from baseport and nat them to dstip, dstport,
   this will create nport new forced destination NAT rules. */
static SshOperationHandle
alg_sip_open_transport_ports(SshAppgwSip alg,
			     SshAppgwContext instance,
			     Boolean initiator_inside,
			     SshUInt16 dstport,
			     SshUInt16 baseport, SshUInt16 nports,
			     SshAppgwSipPortCB callback,
			     void *callback_context)


{
  SipOpenPort op;

  if ((op = ssh_malloc(sizeof(*op))) == NULL ||
      (op->master_op =
       ssh_operation_register(alg_sip_create_abort, op)) == NULL)
    {
      (*callback)(0, 0, callback_context);

      ssh_free(op);
      return NULL;
    }

  op->instance = instance;
  op->baseport = baseport;
  op->dstport = dstport;
  op->nports = nports;
  op->currport = 0;
  op->last_open_handle = 0;
  op->initiator_inside = initiator_inside;
  op->failed = FALSE;

  op->callback = callback;
  op->callback_context = callback_context;

  op->op = NULL;

  SSH_DEBUG(SSH_D_MIDOK, ("init ports: thread %p", &op->thread));
  ssh_fsm_thread_init(&alg->fsm,
		      &op->thread, sip_port_open,
		      NULL_FNPTR, alg_sip_create_destroy,
		      op);

  return op->master_op;
}

static SshUInt16
alg_sip_reserve_ports(SshAppgwSip alg, SshUInt16 nports)
{
  unsigned char patt[4];
  int i, j;
  SshUInt16 port;

  if (nports == 2)
    {
      patt[0] = 0xc0; patt[1] = 0x30; patt[2] = 0x0c; patt[3] = 0x03;
    }
  if (nports == 4)
    {
      patt[0] = 0xf0; patt[2] = 0x0f; patt[2] = 0x00; patt[3] = 0x00;
    }

  /* scan from the last found hole towards the end. */
  for (i = alg->current_offset; i < alg->portmap_size; i++)
    {
      for (j = 0; j < 4; j++)
	{
	  if (patt[j] &&
	      ((alg->portmap[i] & patt[j]) == 0))
	    {
	      port = alg->baseport + (i * 8) + (j * nports);
	      alg->portmap[i] |= patt[j];
	      goto found;
	    }
	}
    }
  /* and from begining towards last found hole if previous failed. */
  for (i = 0; i < alg->current_offset; i++)
    {
      for (j = 0; j < 4; j++)
	{
	  if (patt[j] &&
	      ((alg->portmap[i] & patt[j]) == 0))
	    {
	      port = alg->baseport + (i * 8) + (j * nports);
	      alg->portmap[i] |= patt[j];
	      goto found;
	    }
	}
    }
  return 0;

 found:
  /* Might still fit into same word next time. */
  alg->current_offset = i - 1;
  return port;
}

static void
alg_sip_free_ports(SshAppgwSip alg,
		   SshUInt16 baseport, SshUInt16 nports)
{
  SshUInt16 owords, obits;
  unsigned char pattern = 0;

  owords = (baseport - alg->baseport) / 8;
  obits  = (baseport - alg->baseport) % 8;

  if (nports == 2)
    pattern = 0x03 << (6 - obits);
  if (nports == 4)
    pattern = 0x0f << (4 - obits);

  alg->portmap[owords] &= ~pattern;

  /* we do not record current_offset here, might be a good idea
     thou? */
}

void
alg_sip_close_transport(SshAppgwSip alg,
			SshAppgwContext instance,
			SshUInt16 baseport, SshUInt16 nports)
{
  int i;

  alg_sip_free_ports(alg, baseport, nports);
  for (i = 0; i < nports; i++)
    {
      int index = baseport - alg->baseport + i;

      ssh_appgw_close_port(instance, alg->portmap_handles[index]);
      alg->portmap_handles[index] = 0;
    }
  return;
}

/* Opens nports for RTP transfer. The first opened port will always be
   even, and all of them will be consecutive */
SshOperationHandle
alg_sip_open_transport(SshAppgwSip alg,
		       SshAppgwContext instance,
		       Boolean initiator_inside,
		       SshUInt16 dstport, SshUInt16 nports,
		       SshAppgwSipPortCB callback,
		       void *callback_context)
{
  SshUInt16 port;

  if ((port = alg_sip_reserve_ports(alg, nports)) == 0)
    {
      (*callback)(0, 0, callback_context);
    }

  return alg_sip_open_transport_ports(alg,
				      instance,
				      initiator_inside,
				      dstport, port, nports,
				      callback, callback_context);

}
#endif /* SSHDIST_IPSEC_FIREWALL */

/* eof */
