/*

  winnt_device_io.c

  Copyright:
          Copyright (c) 2009 SFNT Finland Oy.
  All rights reserved.

  Platform dependent kernel mode device I/O helper functions for Windows NT
  series desktop operating systems. 

*/

#ifndef _WIN32_WCE

/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/

#include "sshincludes.h"
#include "device_io.h"
#include "kernel_timeouts.h"

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/
#define SSH_DEBUG_MODULE          "SshInterceptorDeviceIO"

/* Asynchronous I/O requests are canceled if not completed in 6 seconds */
#define SSH_DEVICE_DEFAULT_IRP_TIMEOUT   6000

typedef struct SshInternalIoRequestRec
{
  /* Entry for keeping requests in a linked list */
  LIST_ENTRY link;
  /* I/O request */
  SshDeviceIoRequestStruct request;
  /* Pointer to the owner device */
  SshDeviceIoContext owner;
  /* Pointer to native IRP */
  PIRP irp;
} SshInternalIoRequestStruct, *SshInternalIoRequest;

/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

Boolean
ssh_device_open(SshDeviceIoContext device_context,
                WCHAR *device_name,
                SshDeviceIoOpenParams params)
{
  UNICODE_STRING uc_name;
  OBJECT_ATTRIBUTES oa;
  IO_STATUS_BLOCK iosb;
  ULONG access_mask = GENERIC_READ;
  ULONG share = 0;
  NTSTATUS st;

  SSH_ASSERT(device_context != NULL);
  SSH_ASSERT(device_name != NULL);

  RtlZeroMemory(device_context, sizeof(*device_context));
  InitializeListHead(&device_context->requests);
  ssh_kernel_mutex_init(&device_context->req_list_lock);
  device_context->default_timeout = SSH_DEVICE_DEFAULT_IRP_TIMEOUT;

  if (params)
    {
      device_context->disable_count_ptr = params->disable_count_ptr;
      device_context->requests_pending_ptr = params->requests_pending_ptr;

      if (params->default_timeout)
        device_context->default_timeout = params->default_timeout;

      if (params->write_access)
        access_mask |= GENERIC_WRITE;

      if (!params->exclusive_access)
        share = FILE_SHARE_READ | FILE_SHARE_WRITE;
    }
  else
    {
      access_mask |= GENERIC_WRITE;
      share = FILE_SHARE_READ | FILE_SHARE_WRITE;
    }

  SSH_DEBUG_HEXDUMP(SSH_D_HIGHSTART, 
                    ("Opening I/O device (%s %s access)...",
                     (share == 0) ? "exclusive" : "",
                     ((access_mask & GENERIC_WRITE) == GENERIC_WRITE) ? 
                       "read-write" : "read"),
                    (void *)device_name, 
                    wcslen(device_name) * sizeof(WCHAR));

  RtlInitUnicodeString(&uc_name, device_name);

  InitializeObjectAttributes(&oa, &uc_name, 
                             OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 
                             NULL, NULL);
  RtlZeroMemory(&iosb, sizeof(iosb));
  st = ZwCreateFile(&device_context->handle, 
                    access_mask, 
                    &oa, 
                    &iosb, 
                    0L, 
                    FILE_ATTRIBUTE_NORMAL, 
                    share, 
                    FILE_OPEN_IF, 
                    0L, 
                    NULL, 
                    0L);
  if (!NT_SUCCESS(st))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to open device!"));
      return FALSE;
    }

  /* Retrieve corresponding FILE_OBJECT */
  st = ObReferenceObjectByHandle(device_context->handle, 
                                 access_mask,
                                 NULL, 
                                 KernelMode,
                                 &device_context->file_obj,
                                 NULL);

  if (!NT_SUCCESS(st))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to get file object; closing device"));
      ZwClose(device_context->handle);
      return FALSE;
    }

  /* Retrieve corresponding DEVICE_OBJECT */
  device_context->dev_obj = 
    IoGetRelatedDeviceObject(device_context->file_obj);

  return TRUE;
}


void
ssh_device_close(SshDeviceIoContext device_context)
{
  SSH_ASSERT(device_context != NULL);

  if (device_context->file_obj)
    ObDereferenceObject(device_context->file_obj);

  if (device_context->handle)
    ZwClose(device_context->handle);

  SSH_ASSERT(IsListEmpty(&device_context->requests) != FALSE);
  ssh_kernel_mutex_uninit(&device_context->req_list_lock);
}


NTSTATUS
ssh_device_ioctl_request(SshDeviceIoContext device_context,
                         SshDeviceIoRequest request)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL; 
  SshInternalIoRequest io_req;
  PIO_STACK_LOCATION irp_sp;
  KEVENT completion_event;
  IO_STATUS_BLOCK iosb;
  LONG requests_pending = 0;
  LONG disable_count = 0;
  LONG *pending_ptr = &requests_pending;
  LONG *disable_count_ptr = &disable_count;
  SshUInt32 timeout_ms;

  SSH_ASSERT(device_context != NULL);
  SSH_ASSERT(request != NULL);

  io_req = ssh_calloc(1, sizeof(*io_req));
  if (io_req == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to allocate context for I/O request"));
      return STATUS_NO_MEMORY;
    }
  io_req->owner = device_context;
  io_req->request = *request;

  if (io_req->request.timeout)
    timeout_ms = io_req->request.timeout;
  else
    timeout_ms = device_context->default_timeout;

  /* Init event */
  KeInitializeEvent(&completion_event, NotificationEvent, FALSE);

  io_req->irp = 
    IoBuildDeviceIoControlRequest(io_req->request.ioctl_code,
                                  device_context->dev_obj,
                                  io_req->request.input_buffer, 
                                  io_req->request.input_buff_len,
                                  io_req->request.output_buffer, 
                                  io_req->request.output_buff_len,
                                  (BOOLEAN)
                                  io_req->request.internal_device_control,
                                  &completion_event,
                                  &iosb);



  if (io_req->irp == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to builf device I/O control request"));
      ssh_free(io_req);
      return status;
    }

  irp_sp = IoGetNextIrpStackLocation(io_req->irp);
  irp_sp->DeviceObject = device_context->dev_obj;
  irp_sp->FileObject = device_context->file_obj;

  if (device_context->requests_pending_ptr)
    pending_ptr = device_context->requests_pending_ptr;
  if (device_context->disable_count_ptr)
    disable_count_ptr = device_context->disable_count_ptr;

  ssh_kernel_mutex_lock(&device_context->req_list_lock);
  InsertTailList(&device_context->requests,
                 &io_req->link);
  ssh_kernel_mutex_unlock(&device_context->req_list_lock);

  InterlockedIncrement(pending_ptr);

  if (InterlockedCompareExchange(disable_count_ptr, 0, 0) == 0)
    {
      status = IoCallDriver(device_context->dev_obj, io_req->irp);
      if (status == STATUS_PENDING)
        {
          KeWaitForSingleObject(&completion_event, Executive, 
                                KernelMode, FALSE, NULL);

          /* (STATUS_CANCELLED -> STATUS_UNSUCCESSFUL) */
          if (iosb.Status != STATUS_CANCELLED)
            status = iosb.Status;
        }
    }
  InterlockedDecrement(pending_ptr);

  ssh_kernel_mutex_lock(&device_context->req_list_lock);
  RemoveEntryList(&io_req->link);
  ssh_kernel_mutex_unlock(&device_context->req_list_lock);
 
  if (request->output_size_return)
    {
      switch (status)
        {
        case STATUS_SUCCESS:
        case STATUS_BUFFER_TOO_SMALL:
        case STATUS_BUFFER_OVERFLOW:
          *request->output_size_return = (ULONG)iosb.Information;
          break;

        default:
          *request->output_size_return = 0;
          break;
        }
    }

  ssh_free(io_req);

  return (status);
}

#endif /* _WIN32_WCE */
