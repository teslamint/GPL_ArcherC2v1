/*

  kernel_alloc.c

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All rights reserved.

  Implements the ssh_malloc and the deprecated ssh_xmalloc allocation
  APIs. This is done platform-independently by interfacing to the
  (interceptor's) platform-dependent ssh_kernel_* allocation routines.

*/

#ifndef VXWORKS
#include "sshincludes.h"
#include "kernel_alloc.h"
#include "kernel_mutex.h"

#define SSH_DEBUG_MODULE "SshEngineAlloc"

#ifndef ENGINE_MEMORY_DEBUG
void *
ssh_malloc_flags(size_t size, SshUInt32 flags)
{
  return ssh_kernel_alloc(size, flags);
}

void *
ssh_malloc(size_t size)
{
  return ssh_malloc_flags(size, SSH_KERNEL_ALLOC_NOWAIT);
}

void *
ssh_realloc_flags(void * oldptr, size_t oldsize, size_t newsize,
                  SshUInt32 flags)
{
  void * newptr;

  if (oldptr == NULL)
    return ssh_kernel_alloc(newsize, flags);

  if (newsize <= oldsize)
    return oldptr;

  if ((newptr = ssh_kernel_alloc(newsize, flags)) == NULL)
      return NULL;

  /* newsize > oldsize, see above */
  if (oldsize > 0)
    memcpy(newptr, oldptr, oldsize);

  /* Success, thus we can release the old memory */
  ssh_kernel_free(oldptr);

  return newptr;
}

void *
ssh_realloc(void * oldptr, size_t oldsize, size_t newsize)
{
  return ssh_realloc_flags(oldptr, oldsize, newsize, SSH_KERNEL_ALLOC_NOWAIT);
}

void ssh_free (void * ptr)
{
  if (ptr != NULL)
    ssh_kernel_free(ptr);
}

void*
ssh_calloc_flags (size_t nitems, size_t isize, SshUInt32 flags)
{
  void       * ptr;
  size_t       size;

  size = isize * nitems;

  if ((ptr = ssh_malloc_flags(size ? size : 1, flags)) == NULL)
    return NULL;

  if (size > 0)
    memset(ptr, 0, size);

  return ptr;
}

void *
ssh_calloc(size_t nitems, size_t isize)
{
  return ssh_calloc_flags(nitems, isize, SSH_KERNEL_ALLOC_NOWAIT);
}

void *ssh_strdup (const void * p)
{
  const char  * str;
  char        * cp;

  SSH_PRECOND(p != NULL);

  str = (const char *) p;

  if ((cp = (char *) ssh_malloc(strlen(str) + 1)) == NULL)
    return NULL;

  ssh_strcpy(cp, str);

  return (void *) cp;
}

void * ssh_memdup(const void * p, size_t len)
{
  void        * cp;

  if ((cp = ssh_malloc(len + 1)) == NULL)
    return NULL;

  memcpy(cp, p, (size_t)len);

  ((unsigned char *) cp)[len] = '\0';

  return cp;
}

#else /* ENGINE_MEMORY_DEBUG */

#define MAGIC           0xfeeddeadU

typedef struct mem_debug {
    struct mem_debug    * next;
    size_t                      size;
    void                        * memory;
    const char          * file;
    unsigned int                line;
    Boolean             chained;
    SshUInt32           magic;
} mem_debug_t;

static volatile SshKernelMutex debug_mutex = NULL;
static void * debug_head = NULL;

void ssh_kmalloc_debug_init ()
{
  SshKernelMutex mutex;
  mutex = ssh_kernel_mutex_alloc();
  debug_mutex = mutex;
}

void ssh_kmalloc_debug_uninit ()
{
  mem_debug_t * mem, * keep, * next;
  int count, i;
  struct {
    unsigned int line;
    const char * file;
    void * memory;
    size_t size;
    Boolean chained;
  } * list;
  SshKernelMutex mutex;
  size_t total_leaks;

  /* There should not be any concurrent accesses to uninit routine,
     but let's be safe */
  ssh_kernel_mutex_lock(debug_mutex);

  /* First we need count of all the allocations */
  for (count = 0, mem = debug_head; mem; mem = mem->next)
    count++;

  total_leaks = 0;

  /* Allocate struct for information we need and fill it */
  if ((list = ssh_kernel_alloc(count * sizeof(*list),
                               SSH_KERNEL_ALLOC_NOWAIT)) != NULL)
    {
      for (i = 0, mem = debug_head; mem; mem = mem->next, i++)
        {
          list[i].line = mem->line;
          list[i].file = mem->file;
          list[i].memory = mem->memory;
          list[i].size = mem->size;
          list[i].chained = mem->chained;
          total_leaks += mem->size;
        }
    }

  /* This is full of race conditions -- what if someone is trying to
     lock the mutex? We lose. */
  keep = debug_head;
  mutex = debug_mutex;

  debug_head = NULL;
  debug_mutex = NULL;

  ssh_kernel_mutex_unlock(mutex);
  ssh_kernel_mutex_free(mutex);

  /* Since debug_mutex == NULL, the add_allocation will work but not
     update debug_head */

  if (list)
    {
      for (i = 0; i < count; i++)
        {
          SSH_DEBUG(0, ("Memory leak: %p size %d allocated from %s:%d (%s)",
                        list[i].memory,
                        list[i].size,
                        list[i].file,
                        list[i].line,
                        list[i].chained ? "will free" : "won't free"));
        }

      SSH_DEBUG(0, ("Total leaks: %d bytes in %d allocations",
                    total_leaks, count));

      ssh_kernel_free(list);
    }

  for (mem = keep; mem; mem = next)
    {
      next = mem->next;

      if (mem->chained)
        ssh_kernel_free(mem);
    }
}

static inline void * add_allocation (size_t size,
                                     const char * file,
                                     unsigned int line,
                                     SshUInt32 flags)
{
  char * ptr;
  mem_debug_t * mem;

  ptr = ssh_kernel_alloc(size + sizeof(mem_debug_t), flags);

  if (!ptr)
    return NULL;

  mem = (void *) ptr;
  ptr += sizeof(*mem);

  mem->size = size;
  mem->memory = ptr;
  mem->file = file;
  mem->line = line;
  mem->chained = FALSE;
  mem->magic = MAGIC;

  /* Of course, even this is not race condition free, but quite close */
  if (debug_mutex)
    {
      ssh_kernel_mutex_lock(debug_mutex);

      mem->chained = TRUE;
      mem->next = debug_head;
      debug_head = mem;

      ssh_kernel_mutex_unlock(debug_mutex);
    }


  return (void *) ptr;
}

static inline void remove_allocation (void * _ptr)
{
  mem_debug_t * pp, * mem;
  char * ptr;

  ptr = (char *) _ptr - sizeof(*mem);
  mem = (void *) ptr;

  if (mem->magic != MAGIC)
  {
      SSH_DEBUG(0, ("%s: memory %p magic %x from %s:%d",
                    mem->magic == 0 ? "double free" : "memory underrun",
                    mem->memory, mem->magic, mem->file, mem->line));
  }

  if (debug_mutex && mem->chained)
    {
      ssh_kernel_mutex_lock(debug_mutex);

      if (ptr == debug_head)
        {
          debug_head = mem->next;
          mem->next = NULL;
        }
      else
        {
          for (pp = debug_head; pp; pp = pp->next)
            {
              if (pp->next == (void *) ptr)
                {
                  pp->next = mem->next;
                  mem->next = NULL;
                  break;
                }
            }
        }

      ssh_kernel_mutex_unlock(debug_mutex);
    }

  /* Now mem is no longer in the chain */
  ssh_kernel_free(ptr);
}

void *
ssh_kmalloc_flags_debug (size_t size, SshUInt32 flags,
                         const char * file, int line)
{
  return add_allocation(size, file, line, flags);
}

void *
ssh_kcalloc_flags_debug (unsigned long nitems, unsigned long size,
                         SshUInt32 flags,
                         const char * file, int line)
{
  void * p;

  p = add_allocation(nitems * size, file, line, flags);

  if (!p)
    return NULL;

  memset(p, '\0', nitems * size);

  return p;
}

void *
ssh_krealloc_flags_debug (void * oldptr, size_t oldsize, size_t newsize,
                          SshUInt32 flags,
                          const char * file, int line)
{
  void * newptr;

  if (oldptr == NULL)
    return add_allocation(newsize, file, line, flags);

  if (newsize <= oldsize)
    return oldptr;

  if ((newptr = add_allocation(newsize, file, line, flags))
      == NULL)
    return NULL;

  if (oldsize > 0)
    memcpy(newptr, oldptr, oldsize);

  /* Success, thus we can remove the old allocation */
  remove_allocation(oldptr);

  return newptr;

}

void *
ssh_kmalloc_debug (size_t size,
                   const char * file, int line)
{
  return ssh_kmalloc_flags_debug(size, SSH_KERNEL_ALLOC_NOWAIT, file, line);
}

void *
ssh_kcalloc_debug(unsigned long nitems, unsigned long size,
                  const char * file, int line)
{
  return ssh_kcalloc_flags_debug(nitems, size, SSH_KERNEL_ALLOC_NOWAIT,
                                 file, line);
}

void *
ssh_krealloc_debug(void * oldptr, size_t oldsize, size_t newsize,
                   const char * file, int line)
{
  return ssh_krealloc_flags_debug(oldptr, oldsize, newsize,
                                  SSH_KERNEL_ALLOC_NOWAIT,
                                  file, line);
}

void ssh_kfree_debug (void * ptr, const char * file, int line)
{
  if (ptr != NULL)
    remove_allocation(ptr);
}

void * ssh_kstrdup_debug (const void * p, const char * file, int line)
{
  const char  * str;
  char        * cp;

  SSH_PRECOND(p != NULL);

  str = (const char *) p;

  if ((cp = (char *) add_allocation(strlen(str) + 1,
                                    file, line,
                                    SSH_KERNEL_ALLOC_NOWAIT)) == NULL)
    return NULL;

  ssh_strcpy(cp, str);

  return (void *) cp;

}

void * ssh_kmemdup_debug (const void * p, size_t len,
                          const char * file, int line)
{
  void        * cp;

  if ((cp = add_allocation(len + 1, file, line,
                           SSH_KERNEL_ALLOC_NOWAIT)) == NULL)
    return NULL;

  memcpy(cp, p, (size_t)len);

  ((unsigned char *) cp)[len] = '\0';

  return cp;
}

#endif /* ENGINE_MEMORY_DEBUG */

#endif /* VXWORKS */
