/**
   
   @copyright
   Copyright (c) 2008 - 2010, AuthenTec Oy.  All rights reserved.
   
   linux_procfs.c
   
   Procfs frontend for Linux interceptor.
   
*/


#include "linux_internal.h"

#define SSH_DEBUG_MODULE "SshInterceptorProc"

extern SshInterceptor ssh_interceptor_context;


/************************ Internal utility functions ************************/

/* Use printk instead of SSH_DEBUG macros. */
#ifdef DEBUG_LIGHT
#define SSH_LINUX_PROCFS_DEBUG(x...) if (net_ratelimit()) printk(KERN_INFO x)
#define SSH_LINUX_PROCFS_WARN(x...) printk(KERN_EMERG x)
#endif /* DEBUG_LIGHT */

#ifndef SSH_LINUX_PROCFS_DEBUG
#define SSH_LINUX_PROCFS_DEBUG(x...)
#define SSH_LINUX_PROCFS_WARN(x...)
#endif /* SSH_LINUX_PROCFS_DEBUG */


static int
interceptor_proc_entry_fop_open(SshInterceptorProcEntry entry,
				struct file *file)
{
  /* Allow only one userspace application at a time. */
  write_lock(&entry->lock);
  if (entry->open == TRUE)
    {
      write_unlock(&entry->lock);
      return -EBUSY;
    }

  /* Increment module ref to prohibit module unloading. */
  if (!ssh_linux_module_inc_use_count())
    {
      write_unlock(&entry->lock);
      return -EBUSY;
    }

  file->private_data = ssh_interceptor_context;
  entry->buf_len = 0;
  entry->open = TRUE;

  write_unlock(&entry->lock);

  return 0;
}

static int
interceptor_proc_entry_fop_release(SshInterceptorProcEntry entry)
{
  write_lock(&entry->lock);

  /* Release the module reference. */
  ssh_linux_module_dec_use_count();

  /* Mark proc entry closed */
  entry->open = FALSE;

  write_unlock(&entry->lock);

  return 0;
}

static int interceptor_proc_entry_iop_permission(struct inode *inode,
						 int op
#ifdef LINUX_INODE_OPERATION_PERMISSION_HAS_NAMEIDATA
						 , struct nameidata *nd
#endif /* LINUX_INODE_OPERATION_PERMISSION_HAS_NAMEIDATA */
						 )
{
  if (op & MAY_EXEC)
    return -EACCES;

  if ((op & (MAY_READ | MAY_WRITE)) && 
#ifdef LINUX_HAS_TASK_CRED_STRUCT
      current_euid() == 0
#else
      current->euid == 0
#endif
      )
  {
    return 0;
  }

  return -EACCES;
}

static struct inode_operations common_proc_entry_iops =
{
  .permission = interceptor_proc_entry_iop_permission
};


/************************ Ipm proc entry ************************************/

static ssize_t
interceptor_ipm_proc_entry_fop_read(struct file *file,
				    char __user *buf,
				    size_t len,
				    loff_t *pos)
{
  SshInterceptor interceptor = file->private_data;
  SshInterceptorIpmMsg msg = NULL;
  ssize_t msg_len;

  write_lock(&interceptor->ipm_proc_entry.lock);
  
  /* Allow only one read at a time. */
  if (interceptor->ipm_proc_entry.read_active)
    {
      write_unlock(&interceptor->ipm_proc_entry.lock);
      SSH_LINUX_PROCFS_DEBUG("interceptor_ipm_proc_entry_fop_read: -EBUSY\n");
      return -EBUSY;
    }

  interceptor->ipm_proc_entry.read_active = TRUE;

  /* Continue from the partial message. */
  if (interceptor->ipm_proc_entry.send_msg != NULL)
    msg = interceptor->ipm_proc_entry.send_msg;
  
  write_unlock(&interceptor->ipm_proc_entry.lock);
  
 retry:  
  if (msg == NULL)
    {
      /* Get the next message from send queue. */
      local_bh_disable();
      write_lock(&interceptor->ipm.lock);
      
      /* Take next message from send queue. */
      if (interceptor->ipm.send_queue != NULL)
	{
	  msg = interceptor->ipm.send_queue;
	  
	  interceptor->ipm.send_queue = msg->next;
	  if (msg->next)
	    msg->next->prev = NULL;
	  msg->next = NULL;
	  
	  if (msg == interceptor->ipm.send_queue_tail)
	    interceptor->ipm.send_queue_tail = msg->next;
	}
      
      write_unlock(&interceptor->ipm.lock);
      local_bh_enable();
    }
  
  if (msg == NULL)
    {
      /* Non-blocking mode, fail read. */
      if (file->f_flags & O_NONBLOCK)
	{
	  write_lock(&interceptor->ipm_proc_entry.lock);
	  interceptor->ipm_proc_entry.read_active = FALSE;
	  write_unlock(&interceptor->ipm_proc_entry.lock);
	  
	  return -EAGAIN;
	}
      
      /* Blocking mode, sleep until a message or a signal arrives. */
      interruptible_sleep_on(&interceptor->ipm_proc_entry.wait_queue);
      
      if (signal_pending(current))
	{
	  SSH_LINUX_PROCFS_DEBUG("interceptor_ipm_proc_entry_fop_read: "
				 "-ERESTARTSYS\n");

	  write_lock(&interceptor->ipm_proc_entry.lock);
	  interceptor->ipm_proc_entry.read_active = FALSE;
	  write_unlock(&interceptor->ipm_proc_entry.lock);
	  
	  return -ERESTARTSYS;
	}

      goto retry;
    }
  
  interceptor->ipm_proc_entry.send_msg = msg;

  /* Copy message to userspace. */
  msg_len = msg->len - msg->offset;
  if (len < msg_len)
    msg_len = len;
  
  if (copy_to_user(buf, msg->buf + msg->offset, msg_len))
    {
      SSH_LINUX_PROCFS_WARN("interceptor_ipm_proc_entry_fop_read: "
			    "copy_to_user failed, dropping message\n");

      write_lock(&interceptor->ipm_proc_entry.lock);
      interceptor->ipm_proc_entry.send_msg = NULL;
      interceptor->ipm_proc_entry.read_active = FALSE;
      write_unlock(&interceptor->ipm_proc_entry.lock);

      interceptor_ipm_message_free(interceptor, msg);
      return -EFAULT;
    }
  
  msg->offset += msg_len;
  
  /* Whole message was sent. */
  if (msg->offset >= msg->len)
    {
      write_lock(&interceptor->ipm_proc_entry.lock);
      interceptor->ipm_proc_entry.send_msg = NULL;
      interceptor->ipm_proc_entry.read_active = FALSE;
      write_unlock(&interceptor->ipm_proc_entry.lock);

      interceptor_ipm_message_free(interceptor, msg);
    }
  else
    {
      write_lock(&interceptor->ipm_proc_entry.lock);
      interceptor->ipm_proc_entry.read_active = FALSE;
      write_unlock(&interceptor->ipm_proc_entry.lock);
    }

  return msg_len;
}

static ssize_t
interceptor_ipm_proc_entry_fop_write(struct file *file,
				     const char __user *buf,
				     size_t len,
				     loff_t *pos)
{
  SshInterceptor interceptor = file->private_data;
  size_t total_len, recv_len, consumed, msg_len;
  char *user_buf, *recv_buf;

  /* Check if there is another write going on. */
 retry:
  write_lock(&interceptor->ipm_proc_entry.lock);
  
  if (interceptor->ipm_proc_entry.write_active)
    {
      write_unlock(&interceptor->ipm_proc_entry.lock);

      /* Non-blocking mode, fail write. */
      if (file->f_flags & O_NONBLOCK)
	return -EAGAIN;

      /* Blocking mode, wait until other writes are done. */
      interruptible_sleep_on(&interceptor->ipm_proc_entry.wait_queue);
      
      if (signal_pending(current))
	{
	  SSH_LINUX_PROCFS_DEBUG("interceptor_ipm_proc_entry_fop_write: "
				 "-ERESTARTSYS\n");
	  return -ERESTARTSYS;
	}
      
      goto retry;
    }
  
  interceptor->ipm_proc_entry.write_active = TRUE;
  write_unlock(&interceptor->ipm_proc_entry.lock);

  /* Receive data. */
  total_len = 0;
  user_buf = (char *) buf;
  while (user_buf < (buf + len))
    {
      /* Copy data from user to receive buffer. */
      user_buf = (char *) (buf + total_len);

      recv_buf = (interceptor->ipm_proc_entry.recv_buf 
		  + interceptor->ipm_proc_entry.recv_offset);      
      recv_len = (interceptor->ipm_proc_entry.recv_buf_size
		  - interceptor->ipm_proc_entry.recv_offset);

      /* Break out of the loop if receive buffer is full. */
      if (recv_len == 0)
	break;

      if (recv_len > (len - total_len))
	recv_len = (len - total_len);
      
      if (copy_from_user(recv_buf, user_buf, recv_len))
	{
	  SSH_LINUX_PROCFS_WARN("interceptor_ipm_proc_entry_fop_write: "
				"copy_from_user failed, dropping message\n");
	  
	  write_lock(&interceptor->ipm_proc_entry.lock);
	  interceptor->ipm_proc_entry.write_active = FALSE;	  
	  write_unlock(&interceptor->ipm_proc_entry.lock);
	  
	  wake_up_interruptible(&interceptor->ipm_proc_entry.wait_queue);
	  return -EFAULT;
	}
  
      total_len += recv_len;
      interceptor->ipm_proc_entry.recv_len += recv_len;

      /* Parse ipm messages. */
      consumed = 0;
      while (consumed < interceptor->ipm_proc_entry.recv_len)
	{
	  msg_len = 
	    ssh_interceptor_receive_from_ipm(interceptor->ipm_proc_entry.
					     recv_buf + consumed,
					     interceptor->ipm_proc_entry.
					     recv_len - consumed);

	  consumed += msg_len;

	  /* Need more data. */
	  if (msg_len == 0)
	    break;

	  /* Else continue parsing ipm messages. */
	}

      /* Move unparsed data to beginning of receive buffer. */
      if (consumed > 0)
	{
	  SSH_ASSERT(consumed <= interceptor->ipm_proc_entry.recv_len);

	  if (consumed < interceptor->ipm_proc_entry.recv_len)
	    memmove(interceptor->ipm_proc_entry.recv_buf,
		    interceptor->ipm_proc_entry.recv_buf + consumed,
		    interceptor->ipm_proc_entry.recv_len - consumed);
	  
	  interceptor->ipm_proc_entry.recv_offset = 
	    interceptor->ipm_proc_entry.recv_len - consumed;
	  interceptor->ipm_proc_entry.recv_len -= consumed;
	}

      /* Continue receiving data from user. */
    }

  write_lock(&interceptor->ipm_proc_entry.lock);
  interceptor->ipm_proc_entry.write_active = FALSE;	  
  write_unlock(&interceptor->ipm_proc_entry.lock);

  if (total_len == 0)
    {
      SSH_LINUX_PROCFS_WARN("interceptor_ipm_proc_entry_fop_write: "
                            "Out of receive buffer space\n");
      return -ENOMEM;
    }
  
  return total_len;
}

static unsigned int 
interceptor_ipm_proc_entry_fop_poll(struct file *file,
				    struct poll_table_struct *table)
{
  unsigned int mask = 0;
  SshInterceptor interceptor = file->private_data;
  
  poll_wait(file, &interceptor->ipm_proc_entry.wait_queue, table);

  read_lock(&interceptor->ipm_proc_entry.lock);
  if (interceptor->ipm_proc_entry.send_msg != NULL)
    mask |= (POLLIN | POLLRDNORM);
  read_unlock(&interceptor->ipm_proc_entry.lock);

  if (mask == 0)
    {
      local_bh_disable();
      read_lock(&interceptor->ipm.lock);
      
      if (interceptor->ipm.send_queue != NULL)
	mask |= (POLLIN | POLLRDNORM);
      
      read_unlock(&interceptor->ipm.lock);
      local_bh_enable();
    }

  /* /proc entry is always writable */
  mask |= (POLLOUT | POLLWRNORM);

  return mask;
}

static int
interceptor_ipm_proc_entry_fop_open(struct inode *inode,
				    struct file *file)
{
  write_lock(&ssh_interceptor_context->ipm_proc_entry.lock);

  /* Allow only one read form userspace at a time. */
  if (ssh_interceptor_context->ipm_proc_entry.open)
    {
      write_unlock(&ssh_interceptor_context->ipm_proc_entry.lock);
      SSH_LINUX_PROCFS_DEBUG("interceptor_ipm_proc_entry_fop_open: -EBUSY\n");
      return -EBUSY;
    }

  /* Increment module ref to prohibit module unloading. */
  if (!ssh_linux_module_inc_use_count())
    {
      write_unlock(&ssh_interceptor_context->ipm_proc_entry.lock);
      SSH_LINUX_PROCFS_DEBUG("interceptor_ipm_proc_entry_fop_open: -EBUSY\n");
      return -EBUSY;
    }
  
  file->private_data = ssh_interceptor_context;

  ssh_interceptor_context->ipm_proc_entry.open = TRUE;

  /* Clear receive buffer. */
  ssh_interceptor_context->ipm_proc_entry.recv_offset = 0;
  ssh_interceptor_context->ipm_proc_entry.recv_len = 0;
  
  write_unlock(&ssh_interceptor_context->ipm_proc_entry.lock);
  
  interceptor_ipm_open(ssh_interceptor_context);
  ssh_interceptor_notify_ipm_open(ssh_interceptor_context);

  return 0;
}

static int
interceptor_ipm_proc_entry_fop_release(struct inode *inode,
				       struct file *file)
{
  SshInterceptor interceptor = file->private_data;
  SshInterceptorIpmMsg msg;

  ssh_interceptor_notify_ipm_close(interceptor); 
  interceptor_ipm_close(interceptor);
  
  write_lock(&interceptor->ipm_proc_entry.lock);

  interceptor->ipm_proc_entry.open = FALSE;
  
  /* Release the module reference. */
  ssh_linux_module_dec_use_count();
  
  /* Clear receive buffer. */
  interceptor->ipm_proc_entry.recv_offset = 0;
  interceptor->ipm_proc_entry.recv_len = 0;

  /* Free partial output message */
  msg = interceptor->ipm_proc_entry.send_msg;
  interceptor->ipm_proc_entry.send_msg = NULL;

  write_unlock(&interceptor->ipm_proc_entry.lock);

  if (msg)
    interceptor_ipm_message_free(interceptor, msg);  
  
  return 0;
}

static struct file_operations ipm_proc_entry_fops =
{
  .read = interceptor_ipm_proc_entry_fop_read,
  .write = interceptor_ipm_proc_entry_fop_write,
  .poll = interceptor_ipm_proc_entry_fop_poll,
  .open = interceptor_ipm_proc_entry_fop_open,
  .release = interceptor_ipm_proc_entry_fop_release
};

static Boolean
interceptor_ipm_proc_entry_init(SshInterceptor interceptor)
{
  /* Assert that parent dir exists. */
  SSH_ASSERT(interceptor->proc_dir != NULL);

  /* Initialize proc entry structure. */
  init_waitqueue_head(&interceptor->ipm_proc_entry.wait_queue);
  rwlock_init(&interceptor->ipm_proc_entry.lock);

  interceptor->ipm_proc_entry.open = TRUE;
  interceptor->ipm_proc_entry.write_active = TRUE;
  interceptor->ipm_proc_entry.read_active = TRUE;  

  interceptor->ipm_proc_entry.recv_buf_size = SSH_LINUX_IPM_RECV_BUFFER_SIZE;
  interceptor->ipm_proc_entry.recv_buf = 
    ssh_malloc(interceptor->ipm_proc_entry.recv_buf_size);
  if (interceptor->ipm_proc_entry.recv_buf == NULL)
    return FALSE;

  /* Create entry to procfs. */
  interceptor->ipm_proc_entry.entry =
    create_proc_entry(SSH_PROC_ENGINE, S_IFREG | S_IRUSR | S_IWUSR,
                      interceptor->proc_dir);

  if (interceptor->ipm_proc_entry.entry == NULL)
    return FALSE;

#ifdef LINUX_HAS_PROC_DIR_ENTRY_OWNER
  interceptor->ipm_proc_entry.entry->owner = THIS_MODULE;
#endif

  /* Leave the file operations initially unset so that all operations
     on the proc entry fail initially. The file operations are set later
     in ssh_interceptor_proc_enable(). */
  interceptor->ipm_proc_entry.entry->proc_iops = NULL;
  interceptor->ipm_proc_entry.entry->proc_fops = NULL;
  interceptor->ipm_proc_entry.entry->uid = 0;
  interceptor->ipm_proc_entry.entry->gid = 0;
  interceptor->ipm_proc_entry.entry->size = 0;

  /* Mark proc entry ready for use. */
  interceptor->ipm_proc_entry.open = FALSE;
  interceptor->ipm_proc_entry.write_active = FALSE;
  interceptor->ipm_proc_entry.read_active = FALSE;

  return TRUE;
}

static void
interceptor_ipm_proc_entry_uninit(SshInterceptor interceptor)
{
  if (interceptor->ipm_proc_entry.recv_buf != NULL)
    ssh_free(interceptor->ipm_proc_entry.recv_buf);
  interceptor->ipm_proc_entry.recv_buf = NULL;

  /* This should be safe to do without locking as interceptor code
     does not refer `interceptor->ipm_proc_entry.entry' except in 
     init/uninit. */
  if (interceptor->ipm_proc_entry.entry != NULL)
    remove_proc_entry(interceptor->ipm_proc_entry.entry->name,
		      interceptor->proc_dir);
  interceptor->ipm_proc_entry.entry = NULL;
}


#ifdef DEBUG_LIGHT

/************************ Statistics proc_entry *****************************/

static ssize_t 
interceptor_stats_proc_entry_fop_read(struct file *file,
				      char __user *buf,
				      size_t len,
				      loff_t *pos)
{
  SshInterceptor interceptor = file->private_data;
  ssize_t stats_len;

  /* Check if another read / write is ongoing */
  write_lock(&interceptor->stats_proc_entry.lock);
  if (interceptor->stats_proc_entry.active == TRUE)
    {
      write_unlock(&interceptor->stats_proc_entry.lock);
      return -EBUSY;
    }
  interceptor->stats_proc_entry.active = TRUE;
  write_unlock(&interceptor->stats_proc_entry.lock);

  /* First read. */
  if (*pos == 0)
    {
      spin_lock_bh(&interceptor->statistics_lock);

      stats_len = 0;
      stats_len =
	ssh_snprintf(interceptor->stats_proc_entry.buf, 
		     sizeof(interceptor->stats_proc_entry.buf) - stats_len,
		     "AuthenTec %s Statistics: \n"
		     "Packets: \n"
		     " %llu packets in (%llu bytes)\n"
		     " %llu packets out (%llu bytes)\n"
		     " %llu packets sent (%llu bytes)\n"
		     " %llu errors\n"
		     "Locks: \n"
		     " %llu / %llu locks\n"
		     "Memory: \n"
		     " %llu bytes allocated (%llu bytes max) in "
		     "%llu/%llu blocks (%llu total)\n"
		     " %llu packets allocated (total %llu, %llu failed), "
		     "%llu dup\n"









		     ,
		     ssh_engine_version,

		     interceptor->stats.num_packets_in,
		     interceptor->stats.num_bytes_in,
		     
		     interceptor->stats.num_packets_out,
		     interceptor->stats.num_bytes_out,

		     interceptor->stats.num_packets_sent,
		     interceptor->stats.num_bytes_sent,
		     
		     interceptor->stats.num_errors,

		     interceptor->stats.num_light_locks,
		     interceptor->stats.num_heavy_locks,
		     
		     interceptor->stats.allocated_memory,
		     interceptor->stats.allocated_memory_max,
		     
		     interceptor->stats.num_allocations,
		     interceptor->stats.num_allocations_large,
		     interceptor->stats.num_allocations_total,
		     
		     interceptor->stats.num_allocated_packets,
		     interceptor->stats.num_allocated_packets_total,
		     interceptor->stats.num_failed_allocs,
		     interceptor->stats.num_copied_packets
		     











		     );



      spin_unlock_bh(&interceptor->statistics_lock);
      interceptor->stats_proc_entry.buf_len = stats_len;
    }

  /* No more data to read. Indicate EOF. */
  else if (*pos >= interceptor->stats_proc_entry.buf_len)
    {
      interceptor->stats_proc_entry.buf_len = 0;
      stats_len = 0;
      goto out;
    }

  /* Read at offset *pos. */
  else
    {
      stats_len = interceptor->stats_proc_entry.buf_len - *pos;
    }
  
  /* Truncate message if userspace application 
     did not provide a big enough buffer. */
  if (len < stats_len)
    stats_len = len;
  
  /* Copy data to userspace. */
  if (copy_to_user(buf, interceptor->stats_proc_entry.buf + *pos, stats_len))
    {
      interceptor->stats_proc_entry.buf_len = 0;
      stats_len = -EFAULT;
      goto out;
    }
  
  *pos += stats_len;
  
 out:
  write_lock(&interceptor->stats_proc_entry.lock);
  interceptor->stats_proc_entry.active = FALSE;
  write_unlock(&interceptor->stats_proc_entry.lock);

  return stats_len;
}

static ssize_t
interceptor_stats_proc_entry_fop_write(struct file *file,
				       const char __user *buf,
				       size_t len,
				       loff_t *pos)
{
  SshInterceptor interceptor = file->private_data;
  SshUInt64 allocated_memory, allocated_memory_max, num_allocations, 
    num_allocations_large, num_allocations_total;

  /* Check if another read / write is ongoing */
  write_lock(&interceptor->stats_proc_entry.lock);
  if (interceptor->stats_proc_entry.active == TRUE)
    {
      write_unlock(&interceptor->stats_proc_entry.lock);
      return -EBUSY;
    }
  interceptor->stats_proc_entry.active = TRUE;
  write_unlock(&interceptor->stats_proc_entry.lock);

  /* Writing to statistics /proc entry causes statistics to be cleared. */ 
  spin_lock_bh(&interceptor->statistics_lock);
  
  /* Save some fields used for detecting memory leaks etc. */  
  allocated_memory = interceptor->stats.allocated_memory;
  allocated_memory_max = interceptor->stats.allocated_memory_max;
  num_allocations = interceptor->stats.num_allocations;
  num_allocations_large = interceptor->stats.num_allocations_large;
  num_allocations_total = interceptor->stats.num_allocations_total;

  memset(&interceptor->stats, 0, sizeof(interceptor->stats));
  
  interceptor->stats.allocated_memory = allocated_memory;
  interceptor->stats.allocated_memory_max = allocated_memory_max;
  interceptor->stats.num_allocations = num_allocations;
  interceptor->stats.num_allocations_large = num_allocations_large;
  interceptor->stats.num_allocations_total = num_allocations_total;

  spin_unlock_bh(&interceptor->statistics_lock);
  
  write_lock(&interceptor->stats_proc_entry.lock);
  interceptor->stats_proc_entry.active = FALSE;
  write_unlock(&interceptor->stats_proc_entry.lock);

  return len;
}

static int
interceptor_stats_proc_entry_fop_open(struct inode *inode,
					  struct file *file)
{
  return interceptor_proc_entry_fop_open(&ssh_interceptor_context->
					 stats_proc_entry,
                                         file);
}

static int
interceptor_stats_proc_entry_fop_release(struct inode *inode,
					     struct file *file)
{
  SshInterceptor interceptor = file->private_data;
  return interceptor_proc_entry_fop_release(&interceptor->stats_proc_entry);  
}

static struct file_operations stats_proc_entry_fops =
{
  .read = interceptor_stats_proc_entry_fop_read,
  .write = interceptor_stats_proc_entry_fop_write,
  .open = interceptor_stats_proc_entry_fop_open,
  .release = interceptor_stats_proc_entry_fop_release
};

static Boolean
interceptor_stats_proc_entry_init(SshInterceptor interceptor)
{
  /* Assert that parent dir exists. */
  SSH_ASSERT(interceptor->proc_dir != NULL);

  /* Initialize proc entry structure. */
  rwlock_init(&interceptor->stats_proc_entry.lock);
  interceptor->stats_proc_entry.buf_len = 0;
  interceptor->stats_proc_entry.active = TRUE;
  interceptor->stats_proc_entry.open = TRUE;

  /* Create entry to procfs. */
  interceptor->stats_proc_entry.entry = 
    create_proc_entry(SSH_PROC_STATISTICS, S_IFREG | S_IRUSR | S_IWUSR, 
		      interceptor->proc_dir);
  
  if (interceptor->stats_proc_entry.entry == NULL)
    return FALSE;

#ifdef LINUX_HAS_PROC_DIR_ENTRY_OWNER
  interceptor->stats_proc_entry.entry->owner = THIS_MODULE;
#endif

  /* Leave the file operations initially unset so that all operations
     on the proc entry fail initially. The file operations are set later
     in ssh_interceptor_proc_enable(). */
  interceptor->stats_proc_entry.entry->proc_iops = NULL;
  interceptor->stats_proc_entry.entry->proc_fops = NULL;
  interceptor->stats_proc_entry.entry->uid = 0;
  interceptor->stats_proc_entry.entry->gid = 0;
  interceptor->stats_proc_entry.entry->size = 0;

  /* Mark proc entry ready for use. */
  write_lock(&interceptor->stats_proc_entry.lock);
  interceptor->stats_proc_entry.active = FALSE;
  interceptor->stats_proc_entry.open = FALSE;
  write_unlock(&interceptor->stats_proc_entry.lock);

  return TRUE;
}

static void
interceptor_stats_proc_entry_uninit(SshInterceptor interceptor)
{
  if (interceptor->stats_proc_entry.entry == NULL)
    return;
  
  /* This should be safe to do without locking as interceptor code
     does not refer `interceptor->stats_proc_entry.entry' except in 
     init/uninit. */
  remove_proc_entry(interceptor->stats_proc_entry.entry->name,
		    interceptor->proc_dir);
  interceptor->stats_proc_entry.entry = NULL;
}


/************************ Debug proc_entry **********************************/

static ssize_t
interceptor_debug_proc_entry_fop_read(struct file *file,
				      char __user *buf,
				      size_t len,
				      loff_t *pos)
{
  SshInterceptor interceptor = file->private_data;
  ssize_t debug_string_len;
 
  /* Check if another read / write is ongoing */
  write_lock(&interceptor->debug_proc_entry.lock);
  if (interceptor->debug_proc_entry.active == TRUE)
    {
      write_unlock(&interceptor->debug_proc_entry.lock);
      return -EBUSY;
    }
  interceptor->debug_proc_entry.active = TRUE;
  write_unlock(&interceptor->debug_proc_entry.lock);

  if (*pos == 0)
    {
      debug_string_len = 
	ssh_interceptor_get_debug_level(interceptor,
				    interceptor->debug_proc_entry.buf,
				    sizeof(interceptor->debug_proc_entry.buf));
      interceptor->debug_proc_entry.buf_len = debug_string_len;
    }
  
  else if (*pos >= interceptor->debug_proc_entry.buf_len)
    {
      interceptor->debug_proc_entry.buf_len = 0;
      debug_string_len = 0;
      goto out;
    }

  else
    {
      debug_string_len = interceptor->debug_proc_entry.buf_len - *pos;
    }

  if (len < debug_string_len)
    debug_string_len = len;
  
  if (copy_to_user(buf, interceptor->debug_proc_entry.buf, debug_string_len))
    {
      interceptor->debug_proc_entry.buf_len = 0;
      debug_string_len = -EFAULT;
      goto out;
    }
  
  *pos += debug_string_len;
  
 out:
  write_lock(&interceptor->debug_proc_entry.lock);
  interceptor->debug_proc_entry.active = FALSE;
  write_unlock(&interceptor->debug_proc_entry.lock);

  return debug_string_len;
}

static ssize_t
interceptor_debug_proc_entry_fop_write(struct file *file,
				       const char __user *buf,
				       size_t len,
				       loff_t *pos)
{
  SshInterceptor interceptor = file->private_data;
  ssize_t debug_string_len = sizeof(interceptor->debug_proc_entry.buf);
  
  /* Check if another read / write is ongoing */
  write_lock(&interceptor->debug_proc_entry.lock);
  if (interceptor->debug_proc_entry.active == TRUE)
    {
      write_unlock(&interceptor->debug_proc_entry.lock);
      return -EBUSY;
    }
  interceptor->debug_proc_entry.active = TRUE;
  write_unlock(&interceptor->debug_proc_entry.lock);
  
  if (len < debug_string_len)
    debug_string_len = len;
      
  if (copy_from_user(interceptor->debug_proc_entry.buf, buf, debug_string_len))
    {
      debug_string_len = -EFAULT;
      goto out;
    }

  if (debug_string_len == sizeof(interceptor->debug_proc_entry.buf))
    interceptor->debug_proc_entry.buf[debug_string_len - 1] = '\0';
  else
    interceptor->debug_proc_entry.buf[debug_string_len] = '\0';
  
  ssh_interceptor_set_debug_level(interceptor, 
				  interceptor->debug_proc_entry.buf);

 out:
  write_lock(&interceptor->debug_proc_entry.lock);
  interceptor->debug_proc_entry.active = FALSE;
  write_unlock(&interceptor->debug_proc_entry.lock);
  
  return debug_string_len;
}

static int
interceptor_debug_proc_entry_fop_open(struct inode *inode,
				      struct file *file)
{
  return interceptor_proc_entry_fop_open(&ssh_interceptor_context->
                                         debug_proc_entry,
                                         file);
}

static int
interceptor_debug_proc_entry_fop_release(struct inode *inode,
					 struct file *file)
{
  SshInterceptor interceptor = file->private_data;
  return interceptor_proc_entry_fop_release(&interceptor->debug_proc_entry);
}

static struct file_operations debug_proc_entry_fops =
{
  .read = interceptor_debug_proc_entry_fop_read,
  .write = interceptor_debug_proc_entry_fop_write,
  .open = interceptor_debug_proc_entry_fop_open,
  .release = interceptor_debug_proc_entry_fop_release
};

static Boolean
interceptor_debug_proc_entry_init(SshInterceptor interceptor)
{
  /* Assert that parent dir exists. */
  SSH_ASSERT(interceptor->proc_dir != NULL);

  /* Initialize proc entry structure. */
  rwlock_init(&interceptor->debug_proc_entry.lock);
  interceptor->debug_proc_entry.buf_len = 0;
  interceptor->debug_proc_entry.active = TRUE;
  interceptor->debug_proc_entry.open = TRUE;

  /* Create entry to procfs */
  interceptor->debug_proc_entry.entry = 
    create_proc_entry(SSH_PROC_DEBUG, S_IFREG | S_IRUSR | S_IWUSR, 
		      interceptor->proc_dir);
  
  if (interceptor->debug_proc_entry.entry == NULL)
    return FALSE;

#ifdef LINUX_HAS_PROC_DIR_ENTRY_OWNER
  interceptor->debug_proc_entry.entry->owner = THIS_MODULE;
#endif

  /* Leave the file operations initially unset so that all operations
     on the proc entry fail initially. The file operations are set later
     in ssh_interceptor_proc_enable(). */
  interceptor->debug_proc_entry.entry->proc_iops = NULL;
  interceptor->debug_proc_entry.entry->proc_fops = NULL;
  interceptor->debug_proc_entry.entry->uid = 0;
  interceptor->debug_proc_entry.entry->gid = 0;
  interceptor->debug_proc_entry.entry->size = 0;

  /* Mark proc entry ready for use. */
  write_lock(&interceptor->debug_proc_entry.lock);
  interceptor->debug_proc_entry.active = FALSE;
  interceptor->debug_proc_entry.open = FALSE;
  write_unlock(&interceptor->debug_proc_entry.lock);

  return TRUE;
}

void interceptor_debug_proc_entry_uninit(SshInterceptor interceptor)
{
  if (interceptor->debug_proc_entry.entry == NULL)
    return;
  
  /* This should be safe to do without locking as interceptor code
     does not refer `interceptor->debug_proc_entry.entry' except in 
     init/uninit. */
  remove_proc_entry(interceptor->debug_proc_entry.entry->name,
		    interceptor->proc_dir);
  interceptor->debug_proc_entry.entry = NULL;
}

#endif /* DEBUG_LIGHT */


/************************ Version proc_entry ********************************/

static ssize_t
interceptor_version_proc_entry_fop_read(struct file *file,
					char __user *buf,
					size_t len,
					loff_t *pos)
{
  SshInterceptor interceptor = file->private_data;
  ssize_t version_len;

  /* Check if another read / write is ongoing */
  write_lock(&interceptor->version_proc_entry.lock);
  if (interceptor->version_proc_entry.active == TRUE)
    {
      write_unlock(&interceptor->version_proc_entry.lock);
      return -EBUSY;
    }
  interceptor->version_proc_entry.active = TRUE;
  write_unlock(&interceptor->version_proc_entry.lock);

  if (*pos == 0)
    {
      version_len =
	ssh_snprintf(interceptor->version_proc_entry.buf,
		     sizeof(interceptor->version_proc_entry.buf),
		     "AuthenTec %s built on " __DATE__ " " __TIME__ "\n",
		     ssh_engine_version);
      interceptor->version_proc_entry.buf_len = version_len;
    }
  
  else if (*pos >= interceptor->version_proc_entry.buf_len)
    {
      interceptor->version_proc_entry.buf_len = 0;
      version_len = 0;
      goto out;
    }

  else
    {
      version_len = interceptor->version_proc_entry.buf_len - *pos;
    }

  if (len < version_len)
    version_len = len;

  if (copy_to_user(buf, interceptor->version_proc_entry.buf + *pos, 
		   version_len))
    {
      interceptor->version_proc_entry.buf_len = 0;
      version_len = -EFAULT;
      goto out;
    }

  *pos += version_len;

 out:
  write_lock(&interceptor->version_proc_entry.lock);
  interceptor->version_proc_entry.active = FALSE;
  write_unlock(&interceptor->version_proc_entry.lock);

  return version_len;
}

static int
interceptor_version_proc_entry_fop_open(struct inode *inode,
					struct file *file)
{
  return interceptor_proc_entry_fop_open(&ssh_interceptor_context->
                                         version_proc_entry,
                                         file);
}

static int
interceptor_version_proc_entry_fop_release(struct inode *inode,
					   struct file *file)
{
  SshInterceptor interceptor = file->private_data;
  return interceptor_proc_entry_fop_release(&interceptor->version_proc_entry);
}

static struct file_operations version_proc_entry_fops =
{
  .read = interceptor_version_proc_entry_fop_read,
  .open = interceptor_version_proc_entry_fop_open,
  .release = interceptor_version_proc_entry_fop_release
};

static Boolean
interceptor_version_proc_entry_init(SshInterceptor interceptor)
{
  /* Assert that parent dir exists. */
  SSH_ASSERT(interceptor->proc_dir != NULL);
  
  /* Initialize proc entry structure. */
  rwlock_init(&interceptor->version_proc_entry.lock);
  interceptor->version_proc_entry.buf_len = 0;
  interceptor->version_proc_entry.active = TRUE;
  interceptor->version_proc_entry.open = TRUE;

  /* Create entry to procfs. */
  interceptor->version_proc_entry.entry = 
    create_proc_entry(SSH_PROC_VERSION, S_IFREG | S_IRUSR, 
		      interceptor->proc_dir);
  
  if (interceptor->version_proc_entry.entry == NULL)
    return FALSE;
  
#ifdef LINUX_HAS_PROC_DIR_ENTRY_OWNER
  interceptor->version_proc_entry.entry->owner = THIS_MODULE;
#endif

  /* Leave the file operations initially unset so that all operations
     on the proc entry fail initially. The file operations are set later
     in ssh_interceptor_proc_enable(). */
  interceptor->version_proc_entry.entry->proc_iops = NULL;
  interceptor->version_proc_entry.entry->proc_fops = NULL;
  interceptor->version_proc_entry.entry->uid = 0;
  interceptor->version_proc_entry.entry->gid = 0;
  interceptor->version_proc_entry.entry->size = 0;

  /* Mark proc entry ready for use. */
  write_lock(&interceptor->version_proc_entry.lock);
  interceptor->version_proc_entry.active = FALSE;
  interceptor->version_proc_entry.open = FALSE;
  write_unlock(&interceptor->version_proc_entry.lock);

  return TRUE;
}

static void
interceptor_version_proc_entry_uninit(SshInterceptor interceptor)
{
  if (interceptor->version_proc_entry.entry == NULL)
    return;

  /* This should be safe to do without locking as interceptor code
     does not refer `interceptor->version_proc_entry.entry' except in
     init/uninit. */  
  remove_proc_entry(interceptor->version_proc_entry.entry->name,
		    interceptor->proc_dir);
  interceptor->version_proc_entry.entry = NULL;
}


/************************ Proc init / uninit ********************************/

void ssh_interceptor_proc_enable(SshInterceptor interceptor)
{
  /* Attach file operations to IPM proc entry. After this the connection
     attempts from PM succeed. */
  interceptor->ipm_proc_entry.entry->proc_iops = &common_proc_entry_iops;
  interceptor->ipm_proc_entry.entry->proc_fops = &ipm_proc_entry_fops;

#ifdef DEBUG_LIGHT  
  /* Attach file operations to statistics proc entry. */
  interceptor->stats_proc_entry.entry->proc_iops = &common_proc_entry_iops;
  interceptor->stats_proc_entry.entry->proc_fops = &stats_proc_entry_fops;

  /* Attach file operations to debug proc entry. */
  interceptor->debug_proc_entry.entry->proc_iops = &common_proc_entry_iops;
  interceptor->debug_proc_entry.entry->proc_fops = &debug_proc_entry_fops;
#endif /* DEBUG_LIGHT */

  /* Attach file operations to version proc entry. */
  interceptor->version_proc_entry.entry->proc_iops = &common_proc_entry_iops;
  interceptor->version_proc_entry.entry->proc_fops = &version_proc_entry_fops;
}

Boolean ssh_interceptor_proc_init(SshInterceptor interceptor)
{
  char name[128];

  /* Softirqs are always enabled here. */
  SSH_ASSERT(!in_softirq());

  /* Create a directory under /proc/ */
  ssh_snprintf(name, sizeof(name), "%s%s", SSH_PROC_ROOT, ssh_device_suffix);
  interceptor->proc_dir = create_proc_entry(name, S_IFDIR, NULL);
  
  if (interceptor->proc_dir == NULL)
    goto error;

  if (interceptor_ipm_proc_entry_init(interceptor) == FALSE)
    goto error;

#ifdef DEBUG_LIGHT
  if (interceptor_stats_proc_entry_init(interceptor) == FALSE)
    goto error;

  if (interceptor_debug_proc_entry_init(interceptor) == FALSE)
    goto error;
#endif /* DEBUG_LIGHT */

  if (interceptor_version_proc_entry_init(interceptor) == FALSE)
    goto error;

  return TRUE;

 error:
  SSH_DEBUG(SSH_D_ERROR, ("Could not create /proc/%s", name));

  interceptor_ipm_proc_entry_uninit(interceptor);
#ifdef DEBUG_LIGHT
  interceptor_stats_proc_entry_uninit(interceptor);
  interceptor_debug_proc_entry_uninit(interceptor);
#endif /* DEBUG_LIGHT */
  interceptor_version_proc_entry_uninit(interceptor);

  if (interceptor->proc_dir)
    remove_proc_entry(interceptor->proc_dir->name, NULL);
  interceptor->proc_dir = NULL;

  return FALSE;
}

void ssh_interceptor_proc_uninit(SshInterceptor interceptor)
{
  /* Enable softirqs. */
  SSH_ASSERT(in_softirq());
  local_bh_enable();
  SSH_ASSERT(!in_softirq());

  interceptor_ipm_proc_entry_uninit(interceptor);
#ifdef DEBUG_LIGHT
  interceptor_stats_proc_entry_uninit(interceptor);
  interceptor_debug_proc_entry_uninit(interceptor);
#endif /* DEBUG_LIGHT */
  interceptor_version_proc_entry_uninit(interceptor);

  if (interceptor->proc_dir)
    remove_proc_entry(interceptor->proc_dir->name, NULL);
  interceptor->proc_dir = NULL;

  /* Disable softirqs. */
  local_bh_disable();
  SSH_ASSERT(in_softirq());
}
