/*
 * util_asyncop.c
 *
 * Copyright:
 *       Copyright (c) 2002, 2003, 2005 SFNT Finland Oy.
 *       All rights reserved.
 *
 * Policy manager side implementation of the asynchronous operations.
 */

#include "sshincludes.h"

#ifdef SSHDIST_ASYNCOP
#include "quicksecpm_internal.h"
#include "sshasyncop.h"
#include "sshencode.h"

#define SSH_DEBUG_MODULE "SshIpsecPmAsyncop"

/********************************************** simple-freelist-abstraction  */

#define SSH_USE_SIMPLE_FREELIST





#ifndef __GNUC__
#undef SSH_USE_SIMPLE_FREELIST
#endif /* !__GNUC__ */

#ifdef SSH_GLOBALS_EMULATION
/* Simple freelist does not mix well with globals emulation =>
   disable it if globals emulation is on. */
#undef SSH_USE_SIMPLE_FREELIST
#endif /* SSH_GLOBALS_EMULATION */

#ifndef ADDSTAT
#define ADDSTAT(prefix)
#endif /* !ADDSTAT */

#ifdef SSH_USE_SIMPLE_FREELIST

/* This is simple-freelist abstraction which uses void pointers to keep
   track of data fields. Many of the speed-critical functions could be
   also written as macros, but for now inlined functions are sufficient.

   This is GCC-only code. If porting to other platform, the whole
   thing should be rewritten as macros.

   Therefore the code is only enabled when using GCC.
*/

/* Allocate new simple-freelist. */
static inline Boolean
ssh_sf_allocate(void **head)
{
  *head = NULL;
  return TRUE;
}

static inline void
ssh_sf_free(void *head)
{
  void *next;
  while (head)
    {
      next = *((void **)head);
      ssh_free(head);
      head = next;
    }
}

static inline void *
ssh_sf_pop(void **head, int size)
{
  void *r;

  r = *head;
  if (r)
    {
      *head = *((void **)r);
      ADDSTAT(fastmalloc);
    }
  else
    {
      /* we are out of resources, do not exceed those, return
         allocation failure and the applicatation should recover */
      return NULL;
    }

  return r;
}

static inline void
ssh_sf_push(void **head, void *v)
{
  SSH_ASSERT(v != NULL);

  *((void **)v) = *head;
  *head = v;
}

static inline Boolean
ssh_sf_prealloc(void **head, int size)
{
  void *v;

  v = ssh_malloc(size);
  if (v == NULL) return FALSE;

  *((void **)v) = *head;
  *head = v;
  return TRUE;
}

#define SSH_SF_DEF(prefix) \
static void *prefix##_head; \

#define SSH_SF_INIT(prefix) ssh_sf_allocate(&prefix##_head)

#define SSH_SF_UNINIT(prefix) ssh_sf_free(prefix##_head)

#define SSH_SF_ALLOC(prefix,size) \
 ssh_sf_pop(&prefix##_head, size)

#define SSH_SF_FREE(prefix, value) \
 ssh_sf_push(&prefix##_head, value)

#define SSH_SF_PREALLOC(prefix,size) \
 ssh_sf_prealloc(&prefix##_head, size)

#else /* !SSH_USE_SIMPLE_FREELIST */

#define SSH_SF_INIT(prefix) TRUE
#define SSH_SF_UNINIT(prefix)
#define SSH_SF_ALLOC(prefix, size) ssh_malloc(size)
#define SSH_SF_FREE(prefix, value) ssh_free(value)
#define SSH_SF_DEF(prefix) typedef int shutup_compiler_ ## prefix
#define SSH_SF_PREALLOC(prefix, size)  TRUE

#endif /* SSH_USE_SIMPLE_FREELIST */

/* Fast-use allocation lists */
SSH_SF_DEF(operation_freelist);

/***************************************************** structures & globals  */

/* defines the maximum amount of pending asynchronous operations. */
#define SSH_ASYNCHRONOUS_OPERATIONS_MAX 16

/* defines the maximum size of the asynchronous operation result
   buffer,256 bytes is enough for 2048 bit modp integers */
#define SSH_ASYNCOP_RESULT_MAX 256

/* The asynchronous methods struct */
struct SshAsyncOpMethodsRec ssh_pm_asyncop;

/* A pointer to the local asyncop handle */
typedef struct SshAsyncOpRec *SshAsyncOp;

/* local operation record */
struct SshAsyncOpRec
{
  SshOperationHandle op;
  SshAsyncOpCompletionCB callback;
  void *callback_context;
  Boolean aborted;
};

/******************************************************* policymanager code */

/* abort an asynchronous operation */
static void ssh_pm_asyncop_abort(void *context)
{
  SshAsyncOp asyncop = (SshAsyncOp)context;

  SSH_DEBUG(SSH_D_HIGHSTART, ("called"));

  /* mark this operation aborted, the actual cleanup takes place when
     the callback is received */
  asyncop->aborted = 1;
}

/* Callback function that is called when ssh_pme_asyncop_send
   completes.  The argument `result' describes the status of the
   asynchronous operation.  The arguments `result_data', and
   `result_data_len' are valid only for successful asynchronous
   operations if the `result' has the value `SSH_ASYNC_OP_SUCCESS'.
   This completes a generic asyncop operation, and frees the
   operation. The data is passed to the callback function and then
   freed by the caller (the owner of the data) of this function */
void ssh_pm_asyncop_complete(SshPm pm,
                             SshAsyncOpResult result,
                             const unsigned char *result_data,
                             size_t result_data_len,
                             void *context)
{
  SshAsyncOp asyncop = (SshAsyncOp)context;

  /* unknown operation */
  if (!asyncop)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Bad asyncop message"));
      return;
    }

  SSH_DEBUG(SSH_D_HIGHSTART, ("result=%d", result));

  /* operation aborted? */
  if (asyncop->aborted)
    goto cleanup;

  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Asyncop result"),
                    result_data,
                    result_data_len);

  /* call the callback function */
  (*asyncop->callback)(result,
                       result_data,
                       result_data_len,
                       asyncop->callback_context);

 cleanup:

  /* unregister the operation */
  if (!asyncop->aborted)
    ssh_operation_unregister(asyncop->op);

  /* remove and free the asyncop structure */
  SSH_SF_FREE(operation_freelist, asyncop);

  return;

}

/* Implementation of the execute method of an asynchronous
   operation. In the unified-address space we call the engine asyncop
   function directly, otherwise we use the engine-pm communication
   channel to pass the parameters to the engine. The maximum amount of
   allowed simulatenous operation is controlled by the compile time
   option SSH_ASYNCHRONOUS_OPERATIONS_MAX. If succesful returns an
   operation handle, which can be used for cancelling the
   operation. Otherwise returns NULL */
SshOperationHandle
ssh_pm_asyncop_execute(void *context,
                       SshUInt32 procedure_id,
                       const unsigned char *op_data,
                       size_t op_data_len,
                       SshAsyncOpCompletionCB callback,
                       void *callback_context)
{
  SshPm pm = (SshPm)context;
  SshAsyncOp asyncop = NULL;
  SshOperationHandle op = NULL;

  SSH_DEBUG(SSH_D_HIGHSTART, ("called"));

  /* fast allocate operation structure */
  asyncop = SSH_SF_ALLOC(operation_freelist, sizeof(*op));

  if (!asyncop)
    goto fail;

  /* create and register the operation */
  op = ssh_operation_register(ssh_pm_asyncop_abort, asyncop);

  if (!op)
    goto fail;

  /* fill in the operation parameters */
  asyncop->op = op;
  asyncop->callback = callback;
  asyncop->callback_context = callback_context;
  asyncop->aborted = 0;

  /* Now send the operation to the engine */
  ssh_pme_asyncop(pm->engine,
                  procedure_id,
                  op_data,
                  op_data_len,
                  ssh_pm_asyncop_complete,
                  (void *)asyncop);
  return op;

 fail:
  (*callback)(SSH_ASYNC_OP_ERROR_OTHER,
              NULL, 0,
              callback_context);

  /* free the operation */
  if (asyncop)
    SSH_SF_FREE(operation_freelist, asyncop);
  if (op)
    ssh_operation_unregister(op);

  return NULL;
}

/**************************************************************** init code */

/* initialization function for the asynchronous operations. This is
   called once during the system startup from the policymanger */
Boolean ssh_pm_asyncop_init(SshPm pm)
{
  int i;

  SSH_DEBUG(SSH_D_HIGHSTART, ("called"));

  /* create the operation freelist */
  SSH_SF_INIT(operation_freelist);

  /* pre-allocate the maximum amount of allowed simultaneous operation
     contexts. This had better not fail, since this functions is
     called only once during the startup */
  for (i = 0; i < SSH_ASYNCHRONOUS_OPERATIONS_MAX; i++)
    {
      if (!SSH_SF_PREALLOC(operation_freelist, sizeof(struct SshAsyncOpRec)))
	{
	  SSH_SF_UNINIT(operation_freelist);
	  return FALSE;
	}
    }

  /* Initialize the asynchronous operation communication channel to
     the engine */
  pm->asyncop = ssh_async_op_create(&ssh_pm_asyncop, (void *)pm);

  return TRUE;
}

/* un-initialization function for the asynchronous operations. This is
   called once during the system shutdown from the policymanger */
void ssh_pm_asyncop_uninit(SshPm pm)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("called"));

  /* Destroy the asynchronous operation object `asyncop'. */
  ssh_async_op_destroy(pm->asyncop);

  /* free the operation freelist */
  SSH_SF_UNINIT(operation_freelist);

}

/* the asyncop methods structure */
SSH_RODATA
struct SshAsyncOpMethodsRec ssh_pm_asyncop =
{
  /* execute method */
  ssh_pm_asyncop_execute
};

#endif /* SSHDIST_ASYNCOP */
