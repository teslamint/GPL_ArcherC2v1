/*

  t-adt.c

  Author: Antti Huima <huima@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All rights reserved.

  Created Thu Sep  9 13:27:19 1999.

  */

#include "sshincludes.h"
#include "sshrand.h"
#include "sshdebug.h"
#include "sshbuffer.h"
#include "sshrand.h"
#include "sshregression.h"
#include "sshadt.h"
#include "sshadt_i.h"           /* Needed for testing the internals */
#include "sshadt_assoc.h"
#include "sshadt_list.h"
#include "sshadt_map.h"
#include "sshadt_bag.h"
#include "sshadt_array.h"
#include "sshadt_priority_queue.h"
#include "sshadt_priority_heap.h"
#include "sshadt_conv.h"
#include "sshadt_strmap.h"
#include "sshadt_intmap.h"
#include "sshadt_avltree.h"
#include "sshadt_ranges.h"

#define SSH_DEBUG_MODULE "SshADTTest"

#define T SSH_REGRESSION_TEST_TIME
#define TI SSH_REGRESSION_TEST_WITH_INIT
#define TN(d,f) T(d,f,())


/*****************************************************************************/
/*********************************************************** Standard Tests. */
/*****************************************************************************/

/* It must hold that NUM_ITEMS and RELATIVE_PRIME are relatively prime. */

#define NUM_ITEMS 20000
#define RELATIVE_PRIME 17

typedef struct {
  int i;
  SshADTHeaderStruct header;
} IntRecord;

/* Generic destructors. */

static int destroyed;

static void myalloc_destructor(void *ptr, void *ctx)
{
  ssh_free(ptr);
  destroyed++;
}

static void liballoc_destructor(void *ptr, void *ctx)
{
  SSH_DEBUG(8, ("Liballoc destructor"));
  destroyed++;
}

/* Int ptr hashing. */

static unsigned long int_hash(const void *ptr, void *ctx)
{
  return *((int *)ptr);
}

static int int_cmp(const void *ptr1, const void *ptr2, void *ctx)
{
  int a, b;

  SSH_DEBUG(99, ("[ptr1=%p][ptr2=%p].", ptr1, ptr2));

  /* NULL < anything */
  if (ptr1 == NULL && ptr2 == NULL)
    return 0;

  if (ptr1 == NULL)
    return (-1);

  if (ptr2 == NULL)
    return 1;

  /* otherwise, compare the integers */
  a = *((int *)ptr1);
  b = *((int *)ptr2);

  return a - b;
}

static void *int_dupl(const void *o1, void *ctx)
{
  int *o2 = ssh_malloc(sizeof(int));
  *o2 = *((int *)o1);
  return ((void *)o2);
}

static void *int_dupl_with_header(const void *o1, void *ctx)
{
  IntRecord *o2 = ssh_malloc(sizeof(IntRecord));
  o2->i = ((IntRecord *)o1)->i;
  return ((void *)o2);
}

static void insert_to_voidptr_with_header(SshADTContainer c,
                                          SshADTAbsoluteLocation l,
                                          int i)
{
  IntRecord *ptr = ssh_malloc(sizeof(IntRecord));
  ptr->i = i;
  ssh_adt_insert_to(c, l, ptr);
}

/* String hashing. */

static unsigned long str_hash(const void *ptr, void *ctx)
{
  const char *s = ptr;
  int i;
  int size = strlen(s);
  SshUInt32 h = 0;
  for (i = 0; i < size; i++)
    {
      h = ((h << 19) ^ (h >> 13)) + ((unsigned char *)s)[i];
    }
  return h;
}

static void *str_dup(void *ptr, void *ctx)
{
  return ssh_xstrdup(ptr);
}

static int str_cmp(const void *ptr1, const void *ptr2, void *ctx)
{
  return strcmp(ptr1, ptr2);
}

/********************************************************** Tests for lists. */

/* List container creation. */

SshADTContainer create_list_voidptr(void)
{
  return ssh_adt_create_generic(SSH_ADT_LIST,
                                SSH_ADT_COMPARE, int_cmp,
                                SSH_ADT_DUPLICATE, int_dupl,
                                SSH_ADT_DESTROY, myalloc_destructor,
                                SSH_ADT_ARGS_END);
}

SshADTContainer create_list_voidptr_with_header(void)
{
  return ssh_adt_create_generic(SSH_ADT_LIST,
                                SSH_ADT_COMPARE, int_cmp,
                                SSH_ADT_DUPLICATE, int_dupl_with_header,
                                SSH_ADT_DESTROY, myalloc_destructor,
                                SSH_ADT_HEADER,
                                SSH_ADT_OFFSET_OF(IntRecord, header),
                                SSH_ADT_ARGS_END);
}

SshADTContainer create_list_liballoc(void)
{
  return ssh_adt_create_generic(SSH_ADT_LIST,
                                SSH_ADT_DESTROY, liballoc_destructor,
                                SSH_ADT_COMPARE, int_cmp,
                                SSH_ADT_SIZE, sizeof(int),
                                SSH_ADT_ARGS_END);
}

SshADTContainer create_list_liballoc_with_header(void)
{
  return ssh_adt_create_generic(SSH_ADT_LIST,
                                SSH_ADT_COMPARE, int_cmp,
                                SSH_ADT_DESTROY, liballoc_destructor,
                                SSH_ADT_SIZE, sizeof(IntRecord),
                                SSH_ADT_HEADER,
                                SSH_ADT_OFFSET_OF(IntRecord, header),
                                SSH_ADT_ARGS_END);
}

static void add_voidptr(SshADTContainer c, int i)
{
  int *ptr = ssh_malloc(sizeof(*ptr));
  *ptr = i;
  ssh_adt_insert(c, ptr);
}

static void add_voidptr_with_header(SshADTContainer c, int i)
{
  IntRecord *ptr = ssh_malloc(sizeof(IntRecord));
  ptr->i = i;
  ssh_adt_insert(c, ptr);
}

static void add_liballoc(SshADTContainer c, int i)
{
  ssh_adt_put(c, &i);
}

static void add_liballoc_with_header(SshADTContainer c, int i)
{
  IntRecord rec;
  rec.i = i;
  ssh_adt_put(c, &rec);
}

static Boolean list_check(SshADTContainer (* create)(void),
                          void (* adder)(SshADTContainer, int))
{
  SshADTContainer c;
  int i;
  int *ptr;
  SshADTHandle handle;

#if (NUM_ITEMS < 10)
#error "(NUM_ITEMS < 10)"
#endif

  c = (*(create))();

  for (i = 0; i < NUM_ITEMS; i++)
    {
      (*(adder))(c, i);
    }

# define GN                                                                   \
  handle = ssh_adt_get_handle_to_location(c, SSH_ADT_INDEX(i));               \
  SSH_ASSERT(handle != SSH_ADT_INVALID);                                      \
  SSH_ASSERT(*(int *)ssh_adt_get(c, handle) == i);

  i = 0;               GN;
  i = 3;               GN;
  i = NUM_ITEMS - 1;   GN;
  i = NUM_ITEMS - 2;   GN;
  i = NUM_ITEMS - 5;   GN;

# undef GN

  i = 0;

  for (handle = ssh_adt_enumerate_start(c);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(c, handle))
    {
      ptr = ssh_adt_get(c, handle);
      if (*ptr != i) return FALSE;
      i++;
    }

  handle = ssh_adt_get_handle_to_location(c, SSH_ADT_END);

  i = NUM_ITEMS - 1;

  for (; handle != SSH_ADT_INVALID; handle = ssh_adt_previous(c, handle))
    {
      ptr = ssh_adt_get(c, handle);
      if (*ptr != i) return FALSE;
      i--;
    }

  /* Does get_handle_to_equal at least remotely work? */

  handle = ssh_adt_enumerate_start(c);
  ptr = ssh_adt_get(c, handle);
  handle = ssh_adt_get_handle_to_equal(c, ptr);

  ptr = ssh_adt_get(c, handle);
  if (*ptr != 0)
    return FALSE;

  /* Does get_object_from_equal? */

  handle = ssh_adt_enumerate_start(c);
  ptr = ssh_adt_get(c, handle);
  ptr = ssh_adt_get_object_from_equal(c, ptr);
  if (*ptr != 0)
    return FALSE;

  /* And destroy? */

  destroyed = 0;
  ssh_adt_destroy(c);
  if (destroyed != NUM_ITEMS) return FALSE;

  /* Check sorting. */

  c = (*(create))();

  for (i = 0; i < NUM_ITEMS; i++)
    {
      (*(adder))(c, (i * RELATIVE_PRIME) % NUM_ITEMS);
    }

  ssh_adt_list_sort(c);

  i = 0;

  for (handle = ssh_adt_enumerate_start(c);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(c, handle))
    {
      ptr = ssh_adt_get(c, handle);
      if (*ptr != i) return FALSE;
      i++;
    }

  destroyed = 0;
  ssh_adt_destroy(c);
  if (destroyed != NUM_ITEMS) return FALSE;

  return TRUE;
}


/*********************************************************** Tests for maps. */

static Boolean map_check(void)
{
  SshADTContainer c;
  int i;
  int k;
  SshADTHandle h;

  c = ssh_adt_create_generic(SSH_ADT_MAP,
                             SSH_ADT_HASH, int_hash,
                             SSH_ADT_COMPARE, int_cmp,
                             SSH_ADT_DESTROY, liballoc_destructor,
                             SSH_ADT_SIZE, sizeof(int),
                             SSH_ADT_ARGS_END);

  for (i = 0; i < NUM_ITEMS; i++)
    {
      ssh_adt_put(c, &i);
      k = i;
      h = ssh_adt_get_handle_to_equal(c, &k);
      if (h == SSH_ADT_INVALID) return FALSE;
      ssh_adt_map_attach(c, h, (void *)i);
    }

  for (i = 0; i < NUM_ITEMS; i++)
    {
      k = ssh_rand() % NUM_ITEMS;
      h = ssh_adt_get_handle_to_equal(c, &k);
      if (h == SSH_ADT_INVALID) return FALSE;
      if (ssh_adt_map_lookup(c, h) != ((void *)k)) return FALSE;
    }

  for (i = 0; i < NUM_ITEMS; i++)
    {
      k = i;
      h = ssh_adt_get_handle_to_equal(c, &k);
      if (h == SSH_ADT_INVALID) return FALSE;
      ssh_adt_delete(c, h);
    }

  if (ssh_adt_num_objects(c) != 0) return FALSE;

  /* populate the mapping again for destruction test */
  for (i = 0; i < NUM_ITEMS; i++)
    {
      ssh_adt_put(c, &i);
      k = i;
      h = ssh_adt_get_handle_to_equal(c, &k);
      if (h == SSH_ADT_INVALID) return FALSE;
      ssh_adt_map_attach(c, h, (void *)i);
    }

  destroyed = 0;
  ssh_adt_destroy(c);
  if (destroyed != NUM_ITEMS) return FALSE;
  return TRUE;
}

static Boolean strmap_check(void)
{
  SshADTContainer c;
  char buf[100];
  int i;
  int k;
  SshADTHandle h;

  c = ssh_adt_create_generic(SSH_ADT_MAP,
                             SSH_ADT_HASH, str_hash,
                             SSH_ADT_COMPARE, str_cmp,
                             SSH_ADT_DUPLICATE, str_dup,
                             SSH_ADT_DESTROY, myalloc_destructor,
                             SSH_ADT_ARGS_END);

  for (i = 0; i < NUM_ITEMS; i++)
    {
      ssh_snprintf(buf, sizeof(buf), "%d", i);
      ssh_adt_duplicate(c, buf);
      k = i;
      h = ssh_adt_get_handle_to_equal(c, buf);
      if (h == SSH_ADT_INVALID) return FALSE;
      ssh_adt_map_attach(c, h, (void *)i);
    }

  for (i = 0; i < NUM_ITEMS; i++)
    {
      k = ssh_rand() % NUM_ITEMS;
      ssh_snprintf(buf, sizeof(buf), "%d", k);
      h = ssh_adt_get_handle_to_equal(c, buf);
      if (h == SSH_ADT_INVALID) return FALSE;
      if (ssh_adt_map_lookup(c, h) != ((void *)k)) return FALSE;
    }

  destroyed = 0;
  ssh_adt_destroy(c);
  if (destroyed != NUM_ITEMS) return FALSE;
  return TRUE;
}

static int ref_count;

static void insert_hook(SshADTHandle h, void *ctx)
{
  ref_count++;
}

static void detach_hook(SshADTHandle h, void *ctx)
{
  ref_count++;
}

static Boolean hook_check(void)
{
  int i;
  SshADTContainer c = ssh_adt_create_generic(SSH_ADT_LIST,
                                             SSH_ADT_SIZE, sizeof(int),
                                             SSH_ADT_ARGS_END);

  ssh_adt_initialize_hooks(c);

  c->hooks->insert = insert_hook;
  c->hooks->detach = detach_hook;

  ref_count = 0;

  for (i = 0; i < NUM_ITEMS; i++)
    {
      ssh_adt_put(c, &i);
    }
  for (i = 0; i < NUM_ITEMS; i++)
    {
      ssh_adt_delete_from(c, SSH_ADT_END);
    }
  if (ref_count != 2 * NUM_ITEMS) return FALSE;
  ssh_adt_destroy(c);
  return TRUE;
}

static Boolean unimap_check(void)
{
  int i, k;
  int *p;
  SshADTHandle h1, h2;

  SshADTContainer c1 = ssh_adt_create_generic
    (SSH_ADT_MAP,
     SSH_ADT_HASH, int_hash,
     SSH_ADT_COMPARE, int_cmp,
     SSH_ADT_DESTROY, liballoc_destructor,
     SSH_ADT_SIZE, sizeof(int),
     SSH_ADT_ARGS_END);

  SshADTContainer c2 = ssh_adt_create_generic
    (SSH_ADT_LIST,
     SSH_ADT_DESTROY, liballoc_destructor,
     SSH_ADT_SIZE, sizeof(int),
     SSH_ADT_ARGS_END);

  ssh_adt_associate_unimap(c1, c2);

  destroyed = 0;

  for (i = 0; i < NUM_ITEMS; i++)
    {
      h1 = ssh_adt_put(c1, &i);
      for (k = i; k < i + 4; k++)
        {
          h2 = ssh_adt_put(c2, &k);
          SSH_DEBUG(9, ("h1=%p h2=%p\n", h1, h2));
          ssh_adt_map_attach(c1, h1, h2);
        }
    }

  if (destroyed != NUM_ITEMS * 3) return FALSE;

  for (i = 0; i < NUM_ITEMS; i++)
    {
      h1 = ssh_adt_get_handle_to_equal(c1, &i);
      if (h1 == SSH_ADT_INVALID) return FALSE;
      p = ssh_adt_get(c2, ssh_adt_map_lookup(c1, h1));
      if (p == NULL) return FALSE;
      if (*p != i + 3) return FALSE;
    }

  for (i = 0; i < NUM_ITEMS; i++)
    {
      ssh_adt_map_attach(c1, ssh_adt_get_handle_to_equal(c1, &i),
                         SSH_ADT_INVALID);
    }

  if (destroyed != NUM_ITEMS * 4) return FALSE;
  ssh_adt_destroy(c1);
  ssh_adt_destroy(c2);
  if (destroyed != NUM_ITEMS * 5) return FALSE;
  return TRUE;
}


static Boolean bimap_check(void)
{
  int i, k;
  int *p;
  SshADTHandle h1, h2;

  SshADTContainer c1 = ssh_adt_create_generic
    (SSH_ADT_MAP,
     SSH_ADT_HASH, int_hash,
     SSH_ADT_COMPARE, int_cmp,
     SSH_ADT_DESTROY, liballoc_destructor,
     SSH_ADT_SIZE, sizeof(int),
     SSH_ADT_ARGS_END);

  SshADTContainer c2 = ssh_adt_create_generic
    (SSH_ADT_MAP,
     SSH_ADT_HASH, int_hash,
     SSH_ADT_COMPARE, int_cmp,
     SSH_ADT_DESTROY, liballoc_destructor,
     SSH_ADT_SIZE, sizeof(int),
     SSH_ADT_ARGS_END);

  ssh_adt_associate_bimap(c1, c2);

  destroyed = 0;

  for (i = 0; i < NUM_ITEMS; i++)
    {
      h1 = ssh_adt_put(c1, &i);
      k = i + 10;
      h2 = ssh_adt_put(c2, &k);
      ssh_adt_map_attach(c1, h1, h2);
    }

  for (i = 0; i < NUM_ITEMS; i++)
    {

      k = i + 10;

      h2 = ssh_adt_get_handle_to_equal(c2, &k);
      if (h2 == SSH_ADT_INVALID) return FALSE;
      p = ssh_adt_get(c2, h2);
      if (p == NULL) return FALSE;
      if (*p != k) return FALSE;
      h1 = ssh_adt_map_lookup(c2, h2);
      if (h1 == SSH_ADT_INVALID) return FALSE;
      p = ssh_adt_get(c1, h1);
      if (p == NULL) return FALSE;
      if (*p != i) return FALSE;

      h1 = h2 = SSH_ADT_INVALID; p = NULL;

      h1 = ssh_adt_get_handle_to_equal(c1, &i);
      if (h1 == SSH_ADT_INVALID) return FALSE;
      p = ssh_adt_get(c1, h1);
      if (p == NULL) return FALSE;
      if (*p != i) return FALSE;
      h2 = ssh_adt_map_lookup(c1, h1);
      if (h2 == SSH_ADT_INVALID) return FALSE;
      p = ssh_adt_get(c2, h2);
      if (p == NULL) return FALSE;
      if (*p != k) return FALSE;
    }

  ssh_adt_destroy(c1);
  ssh_adt_destroy(c2);
  if (destroyed != NUM_ITEMS * 2) return FALSE;
  return TRUE;
}


/********************************************************* Tests for arrays. */

static SshADTContainer create_array_voidptr(void)
{
  return ssh_adt_create_generic(SSH_ADT_ARRAY,
                                SSH_ADT_DESTROY, myalloc_destructor,
                                SSH_ADT_ARGS_END);
}

static SshADTContainer create_array_liballoc(void)
{
  return ssh_adt_create_generic(SSH_ADT_ARRAY,
                                SSH_ADT_SIZE, sizeof(int),
                                SSH_ADT_DESTROY, liballoc_destructor,
                                SSH_ADT_ARGS_END);
}

static void array_add_voidptr(SshADTContainer c, int idx, int data)
{
  int *obj = ssh_malloc(sizeof(*obj));
  *obj = data;
  ssh_adt_insert_to(c, SSH_ADT_INDEX(idx), obj);
}

static void array_add_liballoc(SshADTContainer c, int idx, int data)
{
  ssh_adt_put_to(c, SSH_ADT_INDEX(idx), &data);
}

static Boolean array_check(SshADTContainer (* create)(void),
                           void (* add)(SshADTContainer, int idx, int data))
{
  SshADTContainer c;
  int i; int q;
  int check[5000];

  for (i = 0; i < 5000; i++)
    {
      check[i] = -1;
    }

  c = (* create)();

  /* empty arrays */
  SSH_ASSERT(ssh_adt_get_handle_to_location(c, SSH_ADT_DEFAULT) ==
             SSH_ADT_INVALID);

  destroyed = 0;

  for (i = 0; i < NUM_ITEMS; i++)
    {
      q = ssh_rand() % (500 + i);
      if (q >= 5000) q = 4999;
      (* add)(c, q, i);
      check[q] = i;

      if (i % 200 == 199)
        {
          SshADTHandle h;
          h = ssh_adt_enumerate_start(c);
          q = 0;
          while (h != SSH_ADT_INVALID && q < 5000)
            {
              int *obj;
              obj = ssh_adt_get(c, h);

              if ((obj != NULL && (*obj < 0 || *obj >= NUM_ITEMS))
                  || (obj == NULL && check[q] != -1)
                  || (obj != NULL && check[q] != *obj))
                {
                  fprintf(stderr, "%u %d %p %d %d\n", (unsigned int)h, q, obj,
                          check[q], obj==NULL ? -1 : *obj);
                  return FALSE;
                }

              h = ssh_adt_enumerate_next(c, h);
              q++;
            }
        }
    }

  ssh_adt_destroy(c);
  if (destroyed != NUM_ITEMS) return FALSE;
  return TRUE;
}


/*********************************************** Tests for priority heaps. */

static Boolean ph_check(void)
{
#define N  32
  SshADTContainer ph;
  SshADTHandle h, handles[N];
  int i, j, *a;

#if 0
  SshADTHandle lh;
#endif /* 0 */

  /* extern void priority_heap_print(SshADTContainer c); */

  ph = ssh_adt_create_generic(SSH_ADT_PRIORITY_HEAP,
                              SSH_ADT_SIZE, sizeof(int),
                              SSH_ADT_COMPARE, int_cmp,
                              SSH_ADT_DESTROY, liballoc_destructor,
                              SSH_ADT_ARGS_END);

  SSH_ASSERT(ssh_adt_num_objects(ph) == 0);
  SSH_ASSERT(ssh_adt_enumerate_start(ph) == SSH_ADT_INVALID);
  SSH_ASSERT(ssh_adt_get_handle_to_location(ph, SSH_ADT_DEFAULT) ==
             SSH_ADT_INVALID);

  for (i = N-1; i >= 0; i--)
    {
      /* fprintf(stderr, "Inserting %d\n", i); */
      ssh_adt_put(ph, &i);

      handles[i] = h = ssh_adt_get_handle_to_location(ph, SSH_ADT_DEFAULT);
      if (h == SSH_ADT_INVALID)
        {
          fprintf(stderr, "Couldn't get handle\n");
          return FALSE;
        }
      a = ssh_adt_get(ph, h);
      if (*a != i)
        {
          fprintf(stderr, "Expected %d, got %d\n", i, *a);
          return FALSE;
        }

#if 0
      fprintf(stderr, "Enumerating:\n");
      h = ssh_adt_enumerate_start(ph);
      SSH_ASSERT(h != SSH_ADT_INVALID);
      do {
        a = ssh_adt_get(ph, h);
        fprintf(stderr, "  Enumerated %d\n", *a);
        lh = h;
      } while ((h = ssh_adt_enumerate_next(ph, h)) != SSH_ADT_INVALID);

      fprintf(stderr, "Revnumerating:\n");
      SSH_ASSERT(lh != SSH_ADT_INVALID);
      do {
        a = ssh_adt_get(ph, lh);
        fprintf(stderr, "  Revnumerated %d\n", *a);
      } while ((lh = ssh_adt_previous(ph, lh)) != SSH_ADT_INVALID);
#endif
      /* priority_heap_print(ph); */
    }

  for (i = 0; i < N; i++)
    {
      int j = i ^ 13;
      /* fprintf(stderr, "Removing %d:\n", j); */
      ssh_adt_delete(ph, handles[j]);
      /* priority_heap_print(ph); */
    }

  for (i = 40002; i > 0; i--)
    {
      j = ssh_rand();
      ssh_adt_put(ph, &j);
    }

  i = 0;
  for (h = ssh_adt_enumerate_start(ph);
       h != SSH_ADT_INVALID;
       h = ssh_adt_enumerate_next(ph, h))
    {
      if ((int)ssh_adt_get(ph, h) <= i)
        ssh_fatal("X");
    }
  ssh_adt_destroy(ph);
  return TRUE;
}

#undef NUM_ITEMS
#define NUM_ITEMS 5000

typedef struct SshTADTMapHeapRec
{
  SshADTPriorityHeapHeaderStruct heap;
  SshUInt32 id;
  SshADTMapHeaderStruct map;
} *SshTADTMapHeap, SshTADTMapHeapStruct;

SshUInt32 tadt_hash_int_cb(const void *obj, void *context)
{
  const SshTADTMapHeap tmp = (SshTADTMapHeap)obj;
  SSH_ASSERT(tmp->id <= NUM_ITEMS);

  return tmp->id;
}

int tadt_compare_int_cb(const void *obj1, const void *obj2,
                        void *context)
{
   const SshTADTMapHeap tmp1 = (SshTADTMapHeap)obj1,
                        tmp2 = (SshTADTMapHeap)obj2;
   SSH_ASSERT(tmp1->id <= NUM_ITEMS);
   SSH_ASSERT(tmp2->id <= NUM_ITEMS);

   return tmp1->id - tmp2->id;
}



static Boolean ph_map_assoc_check(void)
{
  SshTADTMapHeap tmp, tmp2, tmp3;
  SshADTContainer map;
  SshADTContainer heap;
  int i;
  SshUInt32 id;
  SshADTHandle handle1, handle2, handle3;

  /* For keeping the allocted stuff here. The map and heap should
     not allocated anything. */
  SshADTContainer list;

  map = ssh_adt_create_generic(SSH_ADT_MAP,
                               SSH_ADT_HASH,
                               tadt_hash_int_cb,
                               SSH_ADT_COMPARE,
                               tadt_compare_int_cb,
                               SSH_ADT_HEADER,
                               SSH_ADT_OFFSET_OF(SshTADTMapHeapStruct, map),
                               SSH_ADT_ARGS_END);

  heap = ssh_adt_create_generic(SSH_ADT_PRIORITY_HEAP,
                                SSH_ADT_COMPARE,
                                tadt_compare_int_cb,
                                SSH_ADT_HEADER,
                                SSH_ADT_OFFSET_OF(SshTADTMapHeapStruct, heap),
                                SSH_ADT_ARGS_END);

  list = ssh_adt_create_generic(SSH_ADT_LIST,
                                SSH_ADT_DESTROY,
                                ssh_adt_callback_destroy_free,
                                SSH_ADT_ARGS_END);

  for (i = 1; i < NUM_ITEMS; i++)
    {
      tmp = ssh_xcalloc(1, sizeof(*tmp));

      /* To be able to free later */
      ssh_adt_insert(list, tmp);

      id = i;
      tmp->id = id;

      handle1 = ssh_adt_insert(map, tmp);
      handle2 = ssh_adt_insert(heap, tmp);

      ssh_adt_map_attach(map, handle1, tmp);

      SSH_ASSERT(ssh_adt_num_objects(map) == i );
      SSH_ASSERT(ssh_adt_num_objects(heap) == i);

    }

  /* test remove */
  for (i = 1; i < NUM_ITEMS; i++)
    {
      SshTADTMapHeapStruct tmp_item;

      id = i;
      tmp_item.id = id;

      handle2 = ssh_adt_enumerate_start(heap);
      tmp2 = ssh_adt_get(heap, handle2);
      handle3 = ssh_adt_get_handle_to(map, tmp2);

      handle1 = ssh_adt_get_handle_to_equal(map, &tmp_item);
      SSH_ASSERT(handle1 == handle3);
      tmp = ssh_adt_get(map, handle1);
      tmp3 = ssh_adt_map_lookup(map, handle1);

      SSH_ASSERT(tmp == tmp3);

      ssh_adt_delete(heap, handle2);
      ssh_adt_delete(map, handle1);
      SSH_ASSERT(ssh_adt_num_objects(map) == ssh_adt_num_objects(heap));
    }

  /* Delete the allocated objects. Of course ADT could have handled that
     automatically, but I like the idea of preallocaed objects. */
  for (i = 1; i < NUM_ITEMS; i++)
    {
      handle1 = ssh_adt_enumerate_start(list);
      ssh_adt_delete(list, handle1);
    }

  ssh_adt_destroy(map);
  ssh_adt_destroy(heap);
  ssh_adt_destroy(list);
  return TRUE;
}

/*********************************************** Tests for priority queues. */

#undef NUM_ITEMS
#define NUM_ITEMS 5000

static Boolean pq_check(void)
{
  SshADTContainer pq, check_list;
  SshADTHandle ph, lh;
  int *a, *b;
  int i, item, count, j;

  check_list = create_list_liballoc();
  pq = ssh_adt_create_generic(SSH_ADT_PRIORITY_QUEUE,
                              SSH_ADT_SIZE, sizeof(int),
                              SSH_ADT_COMPARE, int_cmp,
                              SSH_ADT_DESTROY, liballoc_destructor,
                              SSH_ADT_ARGS_END);

  SSH_ASSERT(ssh_adt_num_objects(pq) == 0);
  SSH_ASSERT(ssh_adt_enumerate_start(pq) == SSH_ADT_INVALID);
  SSH_ASSERT(ssh_adt_get_handle_to_location(pq, SSH_ADT_DEFAULT) ==
             SSH_ADT_INVALID);

  count = 0;
  destroyed = 0;

  for (i = 0; i < NUM_ITEMS; i++)
    {
      item = ssh_rand() % 200;

      ssh_adt_put(check_list, &item);
      ssh_adt_put(pq, &item);

      count++;

      if (count > NUM_ITEMS/10)
        {
          if (!(count % 20))
            {
              ssh_adt_list_sort(check_list);
              for (j = 0; j < 20; j++)
                {
                  ph = ssh_adt_get_handle_to_location(pq, SSH_ADT_DEFAULT);
                  lh = ssh_adt_get_handle_to_location(check_list,
                                                      SSH_ADT_BEGINNING);
                  a = ssh_adt_get(pq, ph);
                  b = ssh_adt_get(check_list, lh);

                  if (*a != *b)
                    {
                      fprintf(stderr, "%d <=> %d\n", *a, *b);
                      return FALSE;
                    }

                  ssh_adt_delete(pq, ph);
                  ssh_adt_delete(check_list, lh);
                }
            }
        }
    }

  while ((ph = ssh_adt_get_handle_to_location(pq, SSH_ADT_DEFAULT))
         != SSH_ADT_INVALID)
    {
      SSH_ASSERT(ssh_adt_get(pq, ph) != NULL);
      ssh_adt_delete(pq, ph);
    }

  SSH_ASSERT(ssh_adt_num_objects(pq) == 0);
  SSH_ASSERT(ssh_adt_enumerate_start(pq) == SSH_ADT_INVALID);
  SSH_ASSERT(ssh_adt_get_handle_to_location(pq, SSH_ADT_DEFAULT) ==
             SSH_ADT_INVALID);

  ssh_adt_destroy(check_list);
  ssh_adt_destroy(pq);

  if (destroyed != 2 * NUM_ITEMS) return FALSE;

  /* enumeration, get_handle_to, get_handle_to_equal */

  pq = ssh_adt_create_generic(SSH_ADT_PRIORITY_QUEUE,
                              SSH_ADT_SIZE, sizeof(int),
                              SSH_ADT_COMPARE, int_cmp,
                              SSH_ADT_DESTROY, liballoc_destructor,
                              SSH_ADT_ARGS_END);

  SSH_ASSERT(ssh_adt_enumerate_start(pq) == SSH_ADT_INVALID);

  for (i = 0; i < NUM_ITEMS; i++)
    {
      item = ssh_rand() % 200;
      ssh_adt_put(pq, &item);
    }

  ph = ssh_adt_enumerate_start(pq);
  SSH_ASSERT(ph != SSH_ADT_INVALID);
  do
    {
      a = ssh_adt_get(pq, ph);
      lh = ssh_adt_get_handle_to(pq, a);
      SSH_ASSERT(ph == lh);
    } while ((ph = ssh_adt_enumerate_next(pq, ph)) != SSH_ADT_INVALID);

  /* empty adt, check that it really is empty */

  for (i = 0; i < NUM_ITEMS; i++)
    {
      ph = ssh_adt_get_handle_to_location(pq, SSH_ADT_DEFAULT);
      SSH_ASSERT(ph != SSH_ADT_INVALID);
      ssh_adt_delete(pq, ph);
    }

  SSH_ASSERT(ssh_adt_get_handle_to_location(pq, SSH_ADT_DEFAULT) ==
             SSH_ADT_INVALID);
  SSH_ASSERT(ssh_adt_enumerate_start(pq) == SSH_ADT_INVALID);

  ssh_adt_destroy(pq);

  return TRUE;
}

/****************************************************** Test string mappings */

Boolean conv_strmap_check(void)
{
  SshADTContainer c = ssh_adt_create_strmap();
  char buf[100];

  int i;

  for (i = 0; i < 100; i++)
    {
      ssh_snprintf(buf, sizeof(buf), "foo-%d", i);
      ssh_adt_strmap_add(c, buf, (void *)i);
    }

  for (i = 0; i < 100; i++)
    {
      ssh_snprintf(buf, sizeof(buf), "foo-%d", i);
      if (ssh_adt_strmap_get(c, buf) != (void *)i)
        {
          return FALSE;
        }
      ssh_adt_strmap_remove(c, buf);
    }

  for (i = 0; i < 100; i++)
    {
      ssh_snprintf(buf, sizeof(buf), "foo-%d", i);
      if (ssh_adt_strmap_get(c, buf) != NULL)
        return FALSE;
    }

  ssh_adt_destroy(c);
  return TRUE;
}

/**************************************************** Summary Standard Tests */

static void run_tests(void)
{
  ssh_regression_section("Lists");
  T("List, void ptrs w/ header",
    list_check, (create_list_voidptr_with_header,
                 add_voidptr_with_header));
  T("List, void ptrs", list_check, (create_list_voidptr,
                                            add_voidptr));
  T("List, lib allocated",
    list_check, (create_list_liballoc,
                 add_liballoc));
  T("List, lib allocated w/ header",
    list_check, (create_list_liballoc_with_header,
                 add_liballoc_with_header));

  ssh_regression_section("Maps");

  TN("Basic mapping", map_check);
  TN("String mapping", strmap_check);

  ssh_regression_section("Hooks");

  TN("Hooks", hook_check);

  ssh_regression_section("Hooked containers");

  TN("Unimap", unimap_check);
  TN("Bimap", bimap_check);

  ssh_regression_section("Dynamic arrays");

  T("Array, void ptrs",
    array_check, (create_array_voidptr,
                  array_add_voidptr));
  T("Array, lib allocated",
    array_check, (create_array_liballoc, array_add_liballoc));

  ssh_regression_section("Priority Heaps");

  T("Priority Heaps, lib allocated",
    ph_check, ());

  T("Priority heaps, user allocaed, associated with user allocated int maps ",
    ph_map_assoc_check, ());

  ssh_regression_section("Priority Queues");

  T("Priority Queues, lib allocated",
    pq_check, ());

  ssh_regression_section("Convenience containers");

  T("String map", conv_strmap_check, ());
}


/*****************************************************************************/
/********************************************************* Additional Tests. */
/*****************************************************************************/

#undef NUM_ITEMS
#define NUM_ITEMS 20


/*************************************************************** auxiliaries */

static void DUMP_EL(SshBuffer b,
                    SshADTContainer list,
                    const int debug_level,
                    const char *komma,
                    SshADTHandle h)
{
  void *o;
  char s[1000];

  o = ssh_adt_get(list, h);

  if (o == NULL)
    {
      ssh_snprintf(s, 1000, "%s", "NULL");
    }
  else
    {
      if (debug_level < 5)
        ssh_snprintf(s, 1000, "%i", *((int *) o));
      else
        ssh_snprintf(s, 1000, "%i{%p,%p}", *((int *)o), o, h);
    }

  ssh_buffer_append_cstrs(b, komma, s, NULL);
}

/* Print all elements in ML list style using enumeration methods.  */
static void int_container_print(SshADTContainer list,
                                const char *name,
                                const int debug_level)
{
  SshBuffer b;
  char s[1000];
  SshADTHandle h;

  b = ssh_buffer_allocate();
  ssh_snprintf(s, 1000, "%s=[", name);
  ssh_buffer_append_cstrs(b, s, NULL);

  if ((h = ssh_adt_enumerate_start(list)) != SSH_ADT_INVALID)
    {
      DUMP_EL(b, list, debug_level, "", h);
      while ((h = ssh_adt_enumerate_next(list, h)) != SSH_ADT_INVALID)
        DUMP_EL(b, list, debug_level, ", ", h);
    }

  ssh_buffer_append(b, (const unsigned char *)"]\0", 2);
  SSH_DEBUG(debug_level, ("%s", ssh_buffer_ptr(b)));
  ssh_buffer_free(b);
}

int ssh_adt_container_compare(SshADTContainer c1, SshADTContainer c2,
                              int order_matters)
{
  /* Returns non-zero if c1 contains another set of elements than c2.
     The order of elements as generated by enumerate matters iff
     order_matters is non-zero.  */

  SshADTHandle h;

  if (order_matters)
    {
      SSH_NOTREACHED;
    }
  else
    {
#     define CMP(c1, c2, code)                                                \
        if ((h = ssh_adt_enumerate_start(c1)) != SSH_ADT_INVALID)             \
          {                                                                   \
            do                                                                \
              {                                                               \
                if (ssh_adt_get_handle_to_equal(c2, ssh_adt_get(c1, h)) ==    \
                    SSH_ADT_INVALID)                                          \
                  return code;                                                \
              }                                                               \
            while ((h = ssh_adt_enumerate_next(c1, h)) != SSH_ADT_INVALID);   \
          }

      CMP(c1, c2, 1);
      CMP(c2, c1, -1);
#     undef CMP
    }

  return 0;
}


/***************************** CHECK: list insertion with NULL items allowed */

static Boolean list_check_nullobj(void)
{
  SshADTContainer c;
  SshADTHandle h;
  int i;
  void *o;

  c = create_list_voidptr();
  SSH_DEBUG(4, ("list created."));

  for (i = 0; i < NUM_ITEMS; i++)
    ssh_adt_insert(c, (ssh_rand() % 4) ? ((void *)&i) : NULL);

  if ((h = ssh_adt_enumerate_start(c)) != SSH_ADT_INVALID)
    {
      do
        {
          o = ssh_adt_get(c, h);
          if (o == NULL)
            SSH_DEBUG(5, ("NULL."));
          else
            SSH_DEBUG(5, ("%i.", (int)o));
        }
      while ((h = ssh_adt_enumerate_next(c, h)) != SSH_ADT_INVALID);
    }

  ssh_adt_list_sort(c);

  /* Can't use ssh_adt_destroy directly, as it would free the
     voidptr's, which aren't quite reasonable in this test... */
  while (ssh_adt_num_objects(c) > 0)
    ssh_adt_detach_from(c, SSH_ADT_DEFAULT);
  ssh_adt_destroy(c);

  return TRUE;
}


/***************************************************** CHECK: list insertion */

static Boolean list_check_insert_to(SshADTContainer (* create)(void),
                                    void (* adder)(SshADTContainer, int),
                                    void (* inserter)(SshADTContainer,
                                                      SshADTAbsoluteLocation,
                                                      int))
{
  SshADTContainer c;
  int i;

  c = (*(create))();
  SSH_DEBUG(4, ("list created."));

  for (i = 0; i < NUM_ITEMS; i++) (*(adder))(c, i);

  int_container_print(c, "list", 4);

#define GET(c, l)                                                           \
  (*((int *)                                                                \
     ssh_adt_get((c),                                                       \
                 ssh_adt_get_handle_to_location((c), SSH_ADT_INDEX(l)))))

  SSH_DEBUG(80, ("%i/%i/%i.", GET(c, 3), GET(c, 5), GET(c, 13)));
#undef GET

  for (i = 0; i < NUM_ITEMS * 2; i += 2) (*(inserter))(c, SSH_ADT_INDEX(i), 0);
  int_container_print(c, "list", 4);

  ssh_adt_list_sort(c);
  int_container_print(c, "list", 4);

  ssh_adt_destroy(c);

  return TRUE;
}


/***************************************************************** AVL trees */

static const int num_elements = (int)1e4;

typedef struct {
  int i;
  SshADTHeaderStruct h;
} AvlElementStruct,  *AvlElement;


/************************************************* container generation glue */

static int cmp(const void *o1, const void *o2, void *ctx)
{
  int val, i1, i2;

  SSH_DEBUG(9, ("in"));

  SSH_ASSERT(o1 != NULL);
  SSH_ASSERT(o2 != NULL);

  i1 = ((AvlElement)o1)->i;
  i2 = ((AvlElement)o2)->i;
  val = i1 - i2;

  SSH_DEBUG(9, ("out [%i - %i = %i]", i1, i2, val));

  return val;
}


/* user-allocated memory, user-administrated headers */

static SshADTContainer create_um_uh(SshADTContainerType t)
{
  return ssh_adt_create_generic
    (t,
     SSH_ADT_COMPARE, cmp,
     SSH_ADT_HEADER, SSH_ADT_OFFSET_OF(AvlElementStruct, h),
     SSH_ADT_ARGS_END);
}

static SshADTHandle inject_um(SshADTContainer c, void *o)
{
  return ssh_adt_insert(c, o);
  /* (this works for both um_uh and um_ah) */
}

/* user-allocated memory, adt-administrated headers */

static SshADTContainer create_um_ah(SshADTContainerType t)
{
  return ssh_adt_create_generic
    (t,
     SSH_ADT_COMPARE, cmp,
     SSH_ADT_ARGS_END);
}

/* adt-allocated memory, user-administraded headers */

static SshADTContainer create_am_uh(SshADTContainerType t)
{
  return ssh_adt_create_generic
    (t,
     SSH_ADT_COMPARE, cmp,
     SSH_ADT_SIZE, sizeof(AvlElementStruct),
     SSH_ADT_HEADER, SSH_ADT_OFFSET_OF(AvlElementStruct, h),
     SSH_ADT_ARGS_END);
}

static SshADTHandle inject_am(SshADTContainer c, void *o)
{
  return ssh_adt_put(c, o);  




}

/* adt-allocated memory, adt-administraded headers */

static SshADTContainer create_am_ah(SshADTContainerType t)
{
  return ssh_adt_create_generic
    (t,
     SSH_ADT_COMPARE, cmp,
     SSH_ADT_SIZE, sizeof(AvlElementStruct),
     SSH_ADT_ARGS_END);
}


/******************************************************* contents generation */

/* Generate a list of random numbers that forms a deterministic
   basis for all tree operations.  */

static SshADTContainer mk_contents(AvlElement *keys)
{
  int i;
  AvlElement e, k;
  SshADTContainer list;

  /* perhaps be spontaneous, perhaps not (not that important anyway) */
  {
    FILE *fp;
    int i, c = 1347;
    if ((fp = fopen("/dev/urandom", "r")))
      for (i = 0; i < 10; i++) c *= fgetc(fp);
    srand(c);
  }

  list = ssh_adt_create_generic
    (SSH_ADT_LIST, SSH_ADT_COMPARE, cmp, SSH_ADT_ARGS_END);

  k = ssh_xmalloc(sizeof(*e) * num_elements);
  for (i = 0; i < num_elements; i++)
    {
      e = &k[i];
      e->i = rand() % num_elements;
      SSH_DEBUG(9, ("#%i=%i.", i, e->i));
      ssh_adt_insert(list, e);
    }
  *keys = k;
  return list;
}

static SshADTContainer duplicate_contents(SshADTContainer list)
{
  SshADTContainer new_list;
  SshADTHandle h;

  new_list = ssh_adt_create_generic
    (SSH_ADT_LIST, SSH_ADT_COMPARE, cmp, SSH_ADT_ARGS_END);

  h = ssh_adt_enumerate_start(list);
  while (h != SSH_ADT_INVALID)
    {
      if (ssh_adt_insert(new_list, ssh_adt_get(list, h)) == SSH_ADT_INVALID)
        SSH_NOTREACHED;

      h = ssh_adt_enumerate_next(list, h);
    }

  return new_list;
}

/* Compare a tree agains sorted input list.  */

static void check_sanity_enumerate(SshADTContainer c, SshADTContainer sorted)
{
  SshADTHandle h, i;
  int a, b;

  h = ssh_adt_enumerate_start(c);
  i = ssh_adt_enumerate_start(sorted);

  while (h != SSH_ADT_INVALID && i != SSH_ADT_INVALID)
    {
      a = ((AvlElement)ssh_adt_get(c, h))->i;
      b = *((int *)ssh_adt_get(sorted, i));
      SSH_DEBUG(9, ("%i(tree)=%i(list).", a, b));
      SSH_ASSERT(a == b);

      h = ssh_adt_enumerate_next(c, h);
      i = ssh_adt_enumerate_next(sorted, i);
    }

  SSH_ASSERT(h == SSH_ADT_INVALID && i == SSH_ADT_INVALID);
}


/********************************************** The actual algorithmic stuff */

Boolean tree(SshADTContainer (*create)(SshADTContainerType),
             SshADTHandle (*inject)(SshADTContainer, void *),
             SshADTContainer raw, SshADTContainer sorted,
             Boolean can_detach)
{
  SshADTContainer c;
  SshADTHandle h;

  SSH_DEBUG(4, ("in"));

  SSH_DEBUG(4, ("create empty tree."));
  c = create(SSH_ADT_AVLTREE);

  SSH_DEBUG(4, ("inject."));
  h = ssh_adt_enumerate_start(raw);
  while (h != SSH_ADT_INVALID)
    {
      inject(c, ssh_adt_get(raw, h));
      h = ssh_adt_enumerate_next(raw, h);
    }

  SSH_DEBUG(4, ("enumerate."));
#if 0
  ssh_adt_avltree_int_dump(5, c);
#endif
  check_sanity_enumerate(c, sorted);

  SSH_DEBUG(4, ("remove and reinsert at random."));
  {
    int i, n, odds, num_rounds;
    SshADTAbsoluteLocation l;
    AvlElement e;
    SshADTContainer cache, raw2;

    num_rounds = 500;

    cache = ssh_adt_create_generic
      (SSH_ADT_LIST, SSH_ADT_COMPARE, cmp, SSH_ADT_ARGS_END);
    raw2 = duplicate_contents(raw);

    for (i = 0; i <= num_rounds; i++)
      {
        /* Look up random element in contents.  Detach it from the
           tree and insert it into the cache.  */

        l = SSH_ADT_INDEX(rand() % ssh_adt_num_objects(raw2));
        h = ssh_adt_get_handle_to_location(raw2, l);
        e = ssh_adt_detach(raw2, h);

        SSH_DEBUG(5, ("detaching object #%i=%i.", l, e));
        h = ssh_adt_get_handle_to_equal(c, e);
        SSH_DEBUG(5, ("get_handle_to_equal found h=%i.", h));
        SSH_ASSERT(h != NULL);

        if (can_detach)
          {
            e = ssh_adt_detach(c, h);
          }
        else  /* automatic memory - we need to copy the data out by hand.  */
          {
            memcpy(e, ssh_adt_get(c, h), sizeof(*e));
            ssh_adt_delete(c, h);
          }

        ssh_adt_insert(cache, e);

        /* If the cache has grown big enough, empty it into the tree.  */

        n = ssh_adt_num_objects(cache);
        if (n > 0)
          {
            odds = num_elements / (3 * n);
            if (odds == 0 ||                    /* if the cache is `full'... */
                rand() % odds == 0 ||  /* ... or we feel like emptying it... */
                i == num_rounds)          /* ... or this is the last round.  */
              {
                SSH_DEBUG(5, ("reinjecting %i objects from cache.", n));

                while (TRUE)
                  {
                    h = ssh_adt_get_handle_to_location(cache, SSH_ADT_DEFAULT);
                    if (h == SSH_ADT_INVALID)
                      break;
                    e = ssh_adt_detach(cache, h);
                    ssh_adt_insert(raw2, e);
                    inject(c, e);
                  }
              }
          }
      }

    SSH_ASSERT(ssh_adt_num_objects(cache) == 0);
    ssh_adt_destroy(cache);
    ssh_adt_destroy(raw2);
  };

  SSH_DEBUG(4, ("enumerate again."));
  check_sanity_enumerate(c, sorted);

  SSH_DEBUG(4, ("destroy."));
  ssh_adt_destroy(c);

  SSH_DEBUG(4, ("out"));
  return TRUE;
}


/******************************************************************** ranges */

Boolean avltree_test_glb_lub(void)
{
  SshADTContainer c;
  SshADTHandle h;
  AvlElement e = ssh_malloc(sizeof(*e));

  SSH_DEBUG(4, ("in"));

  c = create_um_ah(SSH_ADT_AVLTREE);

  SSH_DEBUG(5, ("feeding."));
  e->i = 18; inject_um(c, e); e = ssh_malloc(sizeof(*e));
  e->i =  2; inject_um(c, e); e = ssh_malloc(sizeof(*e));
  e->i = 26; inject_um(c, e); e = ssh_malloc(sizeof(*e));
  e->i = 48; inject_um(c, e); e = ssh_malloc(sizeof(*e));
  e->i = 46; inject_um(c, e); e = ssh_malloc(sizeof(*e));
  e->i = 16; inject_um(c, e); e = ssh_malloc(sizeof(*e));
  e->i = 29; inject_um(c, e); e = ssh_malloc(sizeof(*e));
  e->i = 26; inject_um(c, e); e = ssh_malloc(sizeof(*e));
  e->i = 12; inject_um(c, e); e = ssh_malloc(sizeof(*e));
  e->i = 40; inject_um(c, e); e = ssh_malloc(sizeof(*e));
  e->i = 40; inject_um(c, e); e = ssh_malloc(sizeof(*e));
  e->i = 48; inject_um(c, e); e = ssh_malloc(sizeof(*e));
  e->i = 47; inject_um(c, e); e = ssh_malloc(sizeof(*e));
  e->i = 18; inject_um(c, e); e = ssh_malloc(sizeof(*e));
  e->i = 14; inject_um(c, e); e = ssh_malloc(sizeof(*e));
  e->i =  5; inject_um(c, e); e = ssh_malloc(sizeof(*e));
  e->i = 33; inject_um(c, e); e = ssh_malloc(sizeof(*e));
  e->i = 27; inject_um(c, e); e = ssh_malloc(sizeof(*e));
  e->i = 31; inject_um(c, e); e = ssh_malloc(sizeof(*e));
  e->i = 38; inject_um(c, e);

#if 0
  {
    int i;
    for (i = 0; i < 50; i++)
      {
        e = ssh_malloc(sizeof(*e));
        e->i = i;
        h = ssh_adt_get_handle_to_lub(c, e);
        if (h == SSH_ADT_INVALID)
          {
            fprintf(stderr,
                    "  e->i = %i; h = ssh_adt_get_handle_to_lub(c, e);\n"
                    "  SSH_ASSERT(h == SSH_ADT_INVALID);\n", e->i);
          }
        else
          {
            fprintf(stderr,
                    "  e->i = %i; h = ssh_adt_get_handle_to_lub(c, e);\n"
                    "  SSH_ASSERT(h != SSH_ADT_INVALID &&"
                    " *(int *)ssh_adt_get(c, h) == %i);\n",
                    e->i, *(int *)ssh_adt_get(c, h));
          }
      }
  }
#endif

  e = ssh_malloc(sizeof(*e));

  SSH_DEBUG(5, ("glb."));
  e->i = 0; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h == SSH_ADT_INVALID);
  e->i = 1; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h == SSH_ADT_INVALID);
  e->i = 2; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 2);
  e->i = 3; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 2);
  e->i = 4; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 2);
  e->i = 5; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 5);
  e->i = 6; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 5);
  e->i = 7; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 5);
  e->i = 8; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 5);
  e->i = 9; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 5);
  e->i = 10; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 5);
  e->i = 11; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 5);
  e->i = 12; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 12);
  e->i = 13; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 12);
  e->i = 14; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 14);
  e->i = 15; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 14);
  e->i = 16; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 16);
  e->i = 17; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 16);
  e->i = 18; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 18);
  e->i = 19; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 18);
  e->i = 20; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 18);
  e->i = 21; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 18);
  e->i = 22; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 18);
  e->i = 23; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 18);
  e->i = 24; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 18);
  e->i = 25; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 18);
  e->i = 26; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 26);
  e->i = 27; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 27);
  e->i = 28; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 27);
  e->i = 29; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 29);
  e->i = 30; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 29);
  e->i = 31; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 31);
  e->i = 32; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 31);
  e->i = 33; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 33);
  e->i = 34; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 33);
  e->i = 35; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 33);
  e->i = 36; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 33);
  e->i = 37; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 33);
  e->i = 38; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 38);
  e->i = 39; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 38);
  e->i = 40; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 40);
  e->i = 41; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 40);
  e->i = 42; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 40);
  e->i = 43; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 40);
  e->i = 44; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 40);
  e->i = 45; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 40);
  e->i = 46; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 46);
  e->i = 47; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 47);
  e->i = 48; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 48);
  e->i = 49; h = ssh_adt_get_handle_to_glb(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 48);

  SSH_DEBUG(5, ("lub."));
  e->i = 0; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 2);
  e->i = 1; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 2);
  e->i = 2; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 2);
  e->i = 3; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 5);
  e->i = 4; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 5);
  e->i = 5; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 5);
  e->i = 6; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 12);
  e->i = 7; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 12);
  e->i = 8; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 12);
  e->i = 9; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 12);
  e->i = 10; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 12);
  e->i = 11; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 12);
  e->i = 12; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 12);
  e->i = 13; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 14);
  e->i = 14; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 14);
  e->i = 15; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 16);
  e->i = 16; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 16);
  e->i = 17; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 18);
  e->i = 18; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 18);
  e->i = 19; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 26);
  e->i = 20; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 26);
  e->i = 21; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 26);
  e->i = 22; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 26);
  e->i = 23; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 26);
  e->i = 24; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 26);
  e->i = 25; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 26);
  e->i = 26; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 26);
  e->i = 27; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 27);
  e->i = 28; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 29);
  e->i = 29; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 29);
  e->i = 30; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 31);
  e->i = 31; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 31);
  e->i = 32; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 33);
  e->i = 33; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 33);
  e->i = 34; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 38);
  e->i = 35; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 38);
  e->i = 36; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 38);
  e->i = 37; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 38);
  e->i = 38; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 38);
  e->i = 39; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 40);
  e->i = 40; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 40);
  e->i = 41; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 46);
  e->i = 42; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 46);
  e->i = 43; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 46);
  e->i = 44; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 46);
  e->i = 45; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 46);
  e->i = 46; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 46);
  e->i = 47; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 47);
  e->i = 48; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h != SSH_ADT_INVALID && *(int *)ssh_adt_get(c, h) == 48);
  e->i = 49; h = ssh_adt_get_handle_to_lub(c, e);
  SSH_ASSERT(h == SSH_ADT_INVALID);

  SSH_DEBUG(5, ("killing."));
  ssh_free(e);
  while (ssh_adt_num_objects(c) > 0)
    {
      e = ssh_adt_detach_from(c, SSH_ADT_DEFAULT);
      ssh_free(e);
    }
  ssh_adt_destroy(c);

  SSH_DEBUG(4, ("out"));
  return TRUE;
}


void ranges_insert(SshADTContainer c,
                   SshADTHandle (*inject)(SshADTContainer, void *),
                   int ik, int v)
{
  SshADTHandle h;
  AvlElement e;

  e = ssh_malloc(sizeof(*e));
  e->i = (ik);

  if ((h = ssh_adt_get_handle_to_equal(c, e)) == SSH_ADT_INVALID)
    {
      inject(c, e);
      h = ssh_adt_get_handle_to_equal(c, e);
    }
  else
    {
      ssh_free(e);
    }

  SSH_ASSERT(h);
  ssh_adt_map_attach(c, h, (void *)(v));
  ssh_adt_ranges_merge(c);
}

void ranges_dump_ranges(SshADTContainer c)
{
  SshADTHandle h;

  SSH_DEBUG(8, ("> dump_ranges <"));
  h = ssh_adt_enumerate_start(c);
  while (h != SSH_ADT_INVALID)
    {
      int k = *(int *)ssh_adt_get(c, h);
      int *v = ssh_adt_map_lookup(c, h);
      SSH_DEBUG(8, (">  %i %i.", k, (int)v));
      h = ssh_adt_enumerate_next(c, h);
    }
  SSH_DEBUG(8, ("> <"));
}

void ranges_my_delete(SshADTContainer c, int ik)
{
  SshADTHandle h;
  AvlElementStruct e;

  e.i = (ik);
  h = ssh_adt_get_handle_to_equal(c, &e);
  SSH_ASSERT(h);
  ssh_adt_delete(c, h);
  ssh_adt_ranges_merge(c);
}

void ranges_CK(SshADTContainer c, int ik, int expect)
{
  SshADTHandle h;
  AvlElementStruct e;

  e.i = (ik);
  h = ssh_adt_get_handle_to_glb(c, &e);
  if (h == NULL)
    {
      SSH_DEBUG(8, ("%7i ==  (NULL)", (ik)));
      SSH_ASSERT(expect == (int)NULL);
    }
  else
    {
      int find = (int)ssh_adt_map_lookup(c, h);
      SSH_DEBUG(8, ("%7i == %7i", (ik), find));
      SSH_ASSERT(expect == find);
    }
}

Boolean ranges(SshADTContainer (*create)(SshADTContainerType),
               SshADTHandle (*inject)(SshADTContainer, void *))
{
  SshADTContainer c;

  SSH_DEBUG(4, ("in"));

  SSH_DEBUG(4, ("create empty tree."));
  c = create(SSH_ADT_RANGES);

  SSH_DEBUG(4, ("test low level interface."));


  /* write */
  ranges_dump_ranges(c);

  ranges_insert(c, inject, 20, 1);
  ranges_insert(c, inject, 50, 2);

  /* lookup */
  ranges_dump_ranges(c);

  ranges_CK(c, -10, (int)NULL);
  ranges_CK(c, 23, 1);
  ranges_CK(c, 230, 2);

  /* stirr */
  ranges_dump_ranges(c);  ranges_CK(c, -10, (int)NULL); ranges_CK(c, 20, 1);
  ranges_CK(c, 50, 2);

  ranges_insert(c, inject, 24, 1);
  ranges_dump_ranges(c);
  ranges_CK(c, -10, (int)NULL); ranges_CK(c, 20, 1); ranges_CK(c, 50, 2);

  ranges_my_delete(c, 20);
  ranges_dump_ranges(c);
  ranges_CK(c, 22, (int)NULL); ranges_CK(c, 50, 2);

  ranges_insert(c, inject, 24, 1);
  ranges_dump_ranges(c);
  ranges_CK(c, 22, (int)NULL); ranges_CK(c, 24, 1); ranges_CK(c, 50, 2);

  ranges_insert(c, inject, 24, 2);
  ranges_dump_ranges(c);
  ranges_CK(c, 22, (int)NULL); ranges_CK(c, 24, 2);

  ranges_insert(c, inject, 10, 8);
  ranges_dump_ranges(c);
  ranges_CK(c, 9, (int)NULL); ranges_CK(c, 10, 8); ranges_CK(c, 24, 2);

  ranges_insert(c, inject, 38, -1);
  ranges_dump_ranges(c);
  ranges_CK(c, 9, (int)NULL); ranges_CK(c, 10, 8); ranges_CK(c, 24, 2);
  ranges_CK(c, 38, -1);

  ranges_insert(c, inject, 88, 6);
  ranges_dump_ranges(c);
  ranges_CK(c, 9, (int)NULL); ranges_CK(c, 10, 8); ranges_CK(c, 24, 2);
  ranges_CK(c, 38, -1); ranges_CK(c, 88, 6);

  ranges_my_delete(c, 88);
  ranges_dump_ranges(c);
  ranges_CK(c, 9, (int)NULL); ranges_CK(c, 10, 8); ranges_CK(c, 24, 2);
  ranges_CK(c, 38, -1);

  ranges_insert(c, inject, 24, 0);
  ranges_dump_ranges(c);
  ranges_CK(c, 9, (int)NULL); ranges_CK(c, 10, 8); ranges_CK(c, 24, 0);
  ranges_CK(c, 38, -1);

  ranges_my_delete(c, 10);
  ranges_dump_ranges(c);
  ranges_CK(c, 24, (int)NULL); ranges_CK(c, 38, -1);

  ranges_insert(c, inject, 10, 8);
  ranges_dump_ranges(c);
  ranges_CK(c, -1000, (int)NULL); ranges_CK(c, 10, 8); ranges_CK(c, 38, -1);

  ranges_insert(c, inject, 24, 0);
  ranges_dump_ranges(c);
  ranges_CK(c, -1000, (int)NULL); ranges_CK(c, 10, 8); ranges_CK(c, 24, 0);
  ranges_CK(c, 38, -1);

  ranges_my_delete(c, 38);
  ranges_dump_ranges(c);
  ranges_CK(c, -1000, (int)NULL); ranges_CK(c, 10, 8); ranges_CK(c, 24, 0);

  SSH_DEBUG(4, ("done."));

  while (ssh_adt_num_objects(c) > 0)
    ssh_free(ssh_adt_detach_from(c, SSH_ADT_DEFAULT));
  ssh_adt_destroy(c);

  return TRUE;
}

void dump_resource_allocator(unsigned char *msg, SshADTContainer c)
{
#ifdef DEBUG_LIGHT
  ssh_adt_ranges_dump(msg, c);
#endif /* DEBUG_LIGHT */
}

void dump_free_resource_handles(unsigned char *msg, SshADTContainer c)
{
  SshADTHandle h;
  for (h = ssh_adt_enumerate_start(c);
       h != SSH_ADT_INVALID;
       h = ssh_adt_enumerate_next(c, h))
    SSH_DEBUG(0, ("<%s> %i.", msg, (SshUInt32)ssh_adt_get(c, h)));
}

#define NUM_ELEMENTS  37

Boolean resource_allocator(void)
{
  SshADTContainer c, free_resource_handles;
  SshADTHandle h, h2;
  SshUInt32 i, j, k;

  SSH_DEBUG(4, ("in."));

  c = ssh_adt_resource_allocator_create();

  for (i = 0; i < NUM_ELEMENTS; i++)
    {
      if (!ssh_adt_resource_allocator_allocate(c, &j))
        SSH_NOTREACHED;
      if (i != j)
        {
          SSH_DEBUG(0, ("simple allocation failed: %i != %i.", i, j));
          return FALSE;
        }
    }

  /* do allocate and free operations at random for a while.  maintain
     a bag of free resource handles.  each time the resource allocator
     reveils the status of a resource, the bag is checked whether this
     is what we expect.  */
  free_resource_handles =
    ssh_adt_create_generic(SSH_ADT_BAG, SSH_ADT_ARGS_END);

  for (i = 0; i < NUM_ELEMENTS * NUM_ELEMENTS; i++)
    {
      k = ssh_rand() % (2 * NUM_ELEMENTS);
      if (k >= NUM_ELEMENTS)
        {
          SSH_DEBUG(9, ("perhaps allocate something."));

          if (!ssh_adt_resource_allocator_allocate(c, &j))
            SSH_NOTREACHED;

          if (j == NUM_ELEMENTS)
            {
              if (!ssh_adt_resource_allocator_free(c, j))
                SSH_NOTREACHED;
            }
          else if (j < NUM_ELEMENTS)
            {
              h2 = ssh_adt_get_handle_to_equal(free_resource_handles,
                                               (void *)j);
              SSH_ASSERT(h2 != SSH_ADT_INVALID);
              ssh_adt_delete(free_resource_handles, h2);
            }
          else
            SSH_NOTREACHED;
        }
      else
        {
          SSH_DEBUG(9, ("perhaps free something."));

          h = ssh_adt_get_handle_to_glb(c, (void *)(&k));
          h2 = ssh_adt_get_handle_to_equal(free_resource_handles, (void *)k);

          SSH_DEBUG(9, ("[%i %i %i]",
                        k,
                        h ? *(SshUInt32 *)ssh_adt_get(c, h) : -1,
                        h ? (Boolean)ssh_adt_map_lookup(c, h) : -1));

          if (h == SSH_ADT_INVALID  /* k is in [-inf, _) */
              || ssh_adt_map_lookup(c, h) == SSH_ADT_RANGES_ALLOCATED)
            {
              /* k is allocated */
              SSH_ASSERT(h2 == SSH_ADT_INVALID);
              ssh_adt_resource_allocator_free(c, k);
              ssh_adt_insert(free_resource_handles, (void *)k);
            }
          else
            {
              /* k is already free */

              /* dump_resource_allocator("msg", c);
                 dump_free_resource_handles("msg", free_resource_handles); */
              SSH_ASSERT(h2 != SSH_ADT_INVALID);
            }
        }
    }

  ssh_adt_destroy(c);
  ssh_adt_destroy(free_resource_handles);

  SSH_DEBUG(4, ("done."));
  return TRUE;
}


/****************************************************************** mappings */

typedef struct {
  int i;
  int ref_count;
} *AvlImage;

static void mappings_attach_cb(void *i, void *ctx)
{
  AvlImage img = (AvlImage)i;
  SSH_DEBUG(9, ("in"));

  SSH_ASSERT(img != NULL);
  /* (this is enforced by the container, but after all we are here to
     question its sanity...)  */

  SSH_DEBUG(9, ("%p: setting ref_count to %i.", img, img->ref_count + 1));
  img->ref_count++;

  SSH_DEBUG(9, ("out"));
}

static void mappings_detach_cb(void *i, void *ctx)
{
  AvlImage img = (AvlImage)i;
  SSH_DEBUG(9, ("in"));

  if (img != NULL)
    {
      SSH_ASSERT(img->ref_count > 0);
      if (img->ref_count == 1)
        {
          SSH_DEBUG(9, ("%p: this was the last reference.", img));
          ssh_free(img);
          SSH_DEBUG(9, ("free was successful."));
        }
      else
        {
          SSH_DEBUG(9, ("%p: setting ref_count to %i.",
                        img, img->ref_count - 1));
          img->ref_count--;
        }
    }

  SSH_DEBUG(9, ("out"));
}

Boolean mappings(void)
{
# define  num_rounds  num_elements
# define  num_images  30

  SshADTContainer c;
  SshADTHandle h;
  AvlElement key, keys;
  AvlImage img[num_images];
  int i, k;

  for (k = 0; k < 2; k++)
    {
      /* Now that we are at it, we can as well test a few other
         container types that support the generic mapping mechanism.  */

      SshADTContainerType t = NULL;

      switch (k)
        {
        case 0: SSH_DEBUG(4, ("(map)")); t = SSH_ADT_MAP; break;
        case 1: SSH_DEBUG(4, ("(tree)")); t = SSH_ADT_AVLTREE; break;
        }

      c = ssh_adt_create_generic
        (t,
         SSH_ADT_COMPARE, cmp,
         SSH_ADT_MAP_ATTACH, mappings_attach_cb,
         SSH_ADT_MAP_DETACH, mappings_detach_cb,
         SSH_ADT_HEADER, SSH_ADT_OFFSET_OF(AvlElementStruct, h),
         SSH_ADT_ARGS_END);

      for (i = 0; i < num_images; i++)
        {
          img[i] = ssh_malloc(sizeof(*img[i]));
          img[i]->i = i;
          img[i]->ref_count = 0;
        }

      /* Insert some random integer keys that map on themselves.
         Need to store keys, as they are user managed. */
      keys = ssh_xmalloc(num_rounds * sizeof(*key));

      for (i = 0; i < num_rounds; i++)
        {
          key = &keys[i];
          key->i = i;

          h = ssh_adt_insert(c, key);
          ssh_adt_map_attach(c, h, img[rand() % num_images]);
        }
      /* Destruction will hopefully not leave too many memory leaks.  */
      ssh_adt_destroy(c);
      ssh_free(keys);
    }

  return TRUE;
}


/********************************************** intmap convenience interface */

static Boolean intmap_test(void)
{
  SshADTContainer c;
  int i;
  unsigned char *value;

  c = ssh_adt_xcreate_intmap(NULL_FNPTR, ssh_adt_callback_destroy_free);
  SSH_DEBUG(4, ("container created."));

  for (i = 0; i < 10; i++)
    ssh_adt_intmap_add(c, i, ssh_xstrdup("string"));

  value = ssh_adt_intmap_get(c, 3);
  if (strcmp(value, "string"))
    {
      SSH_DEBUG(0, ("ssh_adt_intmap_get returned '%s'", value));
      return FALSE;
    }

  for (i = 3; i < 7; i++)
    ssh_adt_intmap_remove(c, i);

  ssh_adt_intmap_set(c, 2, ssh_xstrdup("foo"));
  ssh_adt_intmap_add(c, 1092, ssh_xstrdup("bar"));

  {
    SshADTHandle h = ssh_adt_enumerate_start(c);
    while (h != SSH_ADT_INVALID)
      {
        SSH_DEBUG(5, ("%i -> '%s'.",
                      *(int *)ssh_adt_get(c, h),
                      (unsigned char *)ssh_adt_map_lookup(c, h)));
        h = ssh_adt_enumerate_next(c, h);
      }
  }

  if (ssh_adt_intmap_exists(c, 4) || !ssh_adt_intmap_exists(c, 1092))
    {
      SSH_DEBUG(0, ("existence check is broken."));
      return FALSE;
    }

  value = ssh_adt_intmap_get(c, 2);
  if (strcmp(value, "foo"))
    {
      SSH_DEBUG(0, ("ssh_adt_intmap_get returned '%s'", value));
      return FALSE;
    }

  value = ssh_adt_intmap_get(c, 1092);
  if (strcmp(value, "bar"))
    {
      SSH_DEBUG(0, ("ssh_adt_intmap_get returned '%s'", value));
      return FALSE;
    }

  SSH_DEBUG(4, ("freeing..."));
  ssh_adt_destroy(c);
  SSH_DEBUG(4, ("everything ok."));

  return TRUE;
}


/******************************************************************** driver */

static void run_additional_tests(void)
{
  AvlElement keys;

  ssh_regression_section("Extended: Lists");

  T("List with NULL objects (only for void pointers / liballoked header)",
    list_check_nullobj, ());

  T("List, insert_to (2 = void pointers / inlined header)",
    list_check_insert_to, (create_list_voidptr_with_header,
                           add_voidptr_with_header,
                           insert_to_voidptr_with_header));

  ssh_regression_section("Extended: Things");

  T("intmap", intmap_test, ());

  ssh_regression_section("Extended: AVL trees");

  {
    SshADTContainer raw, sorted;

    raw = mk_contents(&keys);
    sorted = duplicate_contents(raw);
    ssh_adt_list_sort(sorted);

    /* standard trees */

    T("tree() / user memory / abstract headers.",
      tree, (create_um_ah, inject_um, raw, sorted, TRUE));

    T("tree() / user memory / inlined headers.",
      tree, (create_um_uh, inject_um, raw, sorted, TRUE));

    T("tree() / adt allocated memory / abstract headers.",
      tree, (create_am_ah, inject_am, raw, sorted, FALSE));

    T("tree() / adt allocated memory / inlined headers",
      tree, (create_am_uh, inject_am, raw, sorted, FALSE));

    ssh_adt_destroy(raw);
    ssh_adt_destroy(sorted);
    ssh_xfree(keys);

    /* tree mappings */

    T("tree mappings.", mappings, ());

    /* glb, lub */
    T("glb, lub.", avltree_test_glb_lub, ());























  }
}


/*****************************************************************************/
/*********************************** Code that made previous bugs appearent. */
/*****************************************************************************/

void old_bug_1_cb(void *obj, void *context)
{
  ssh_free(obj);
}

void old_bug_1(void)
{
  SshADTContainer c;
  SshADTHandle h;
  void *test_obj;
  c = ssh_adt_xcreate_strmap(NULL_FNPTR, old_bug_1_cb);
  test_obj = ssh_xmalloc(10);
  ssh_adt_strmap_add(c, "FOO", test_obj);
  h = ssh_adt_get_handle_to_equal(c, "FOO");
  ssh_adt_destroy(c);
}

void bug_fixes(void)
{
  old_bug_1();
}


/*****************************************************************************/
/********************************************************************* Main. */
/*****************************************************************************/

int main(int argc, char **argv)
{
  ph_map_assoc_check();
  fprintf(stderr, "running bug reintroduction prevention program...");
  bug_fixes();
  fprintf(stderr, " ok.\n");

  ssh_regression_init(&argc, &argv, "ADT Library", "fis@ssh.fi");

  ssh_debug_set_level_string("SshADT*=3,SshADTTest=0");

  run_tests();
  run_additional_tests();
  ssh_regression_finish();
  /* Not reached. */
  exit(1);
}
