/*
` *
 *  t-http-kvhash.c
 *
 *  Copyright:
 * 	Copyright (c) 2002 - 2005 SFNT Finland Oy.
 * 	All rights reserved.
 *
 */

#include "sshincludes.h"
#include "ssheloop.h"
#include "sshhttp.h"
#include "sshhttpi.h"

#define SSH_ERROR(msg)                  \
do                                      \
  {                                     \
    fprintf(stderr, "%s\n", msg);       \
    errors++;                           \
  }                                     \
while (0)

int
test(SshHttpKvHash hash, Boolean insensitive)
{
  const char *value;
  int errors = 0;

  ssh_http_kvhash_put(hash, "a", 1, "1", 1);
  ssh_http_kvhash_put(hash, "A", 1, "2", 1);
  ssh_http_kvhash_put(hash, "a", 1, "3", 1);
  ssh_http_kvhash_put(hash, "A", 1, "4", 1);
  ssh_http_kvhash_put(hash, "a", 1, "5", 1);
  ssh_http_kvhash_put(hash, "A", 1, "6", 1);
  ssh_http_kvhash_put(hash, "a", 1, "7", 1);

  value = ssh_http_kvhash_get(hash, "A");
  if (value)
    {
      if (insensitive)
        {
          if (strcmp(value, "1,2,3,4,5,6,7") != 0)
            SSH_ERROR("multiple puts produces strange value");
        }
      else
        {
          if (strcmp(value, "2,4,6") != 0)
            SSH_ERROR("multiple puts produces strange value");
        }
    }
  else
    {
      SSH_ERROR("ssh_http_kvhash_get() failed: insensitive");
    }

  ssh_http_kvhash_clear(hash);

  ssh_http_kvhash_put(hash, "A", 1, "foo", 3);
  value = ssh_http_kvhash_get(hash, "A");
  if (value)
    {
      if (strcmp(value, "foo") != 0)
        SSH_ERROR("ssh_http_kvhash_clear() did not clear hash");
    }
  else
    {
      SSH_ERROR("ssh_http_kvhash_get() failed: insensitive");
    }

  ssh_http_kvhash_clear(hash);

  ssh_http_kvhash_put_cstrs(hash, "a", "1");
  ssh_http_kvhash_put_cstrs(hash, "A", "2");
  ssh_http_kvhash_put_cstrs(hash, "a", "3");
  ssh_http_kvhash_put_cstrs(hash, "A", "4");
  ssh_http_kvhash_put_cstrs(hash, "a", "5");

  value = ssh_http_kvhash_get(hash, "A");
  if (value)
    {
      if (insensitive)
        {
          if (strcmp(value, "1,2,3,4,5") != 0)
            SSH_ERROR("multiple puts produces strange value");
        }
      else
        {
          if (strcmp(value, "2,4") != 0)
            SSH_ERROR("multiple puts produces strange value");
        }
    }
  else
    {
      SSH_ERROR("ssh_http_kvhash_get() failed: insensitive");
    }

  ssh_http_kvhash_clear(hash);

  ssh_http_kvhash_put_cstrs(hash, "A", "1");

  ssh_http_kvhash_append_last(hash, "2", 1);
  ssh_http_kvhash_append_last(hash, "3", 1);
  ssh_http_kvhash_append_last(hash, "4", 1);
  ssh_http_kvhash_append_last(hash, "5", 1);
  ssh_http_kvhash_append_last(hash, "6", 1);
  ssh_http_kvhash_append_last(hash, "7", 1);

  value = ssh_http_kvhash_get(hash, "A");
  if (value)
    {
      if (strcmp(value, "1234567") != 0)
        SSH_ERROR("multiple puts produces strange value");
    }
  else
    {
      SSH_ERROR("ssh_http_kvhash_get() failed: insensitive");
    }

  if (!ssh_http_kvhash_remove(hash, "A"))
    SSH_ERROR("Could not remove known key");

  value = ssh_http_kvhash_get(hash, "A");
  if (value != NULL)
    SSH_ERROR("Removed key still in the hash");

  ssh_http_kvhash_clear(hash);

  ssh_http_kvhash_put_cstrs(hash, "A", "A");
  ssh_http_kvhash_put_cstrs(hash, "B", "B");
  ssh_http_kvhash_put_cstrs(hash, "C", "C");
  ssh_http_kvhash_put_cstrs(hash, "D", "D");
  ssh_http_kvhash_put_cstrs(hash, "E", "E");

  {
    unsigned char *key;
    unsigned char *value;
    SshUInt32 num_items = 0;

    for (ssh_http_kvhash_reset_index(hash);
         ssh_http_kvhash_get_next(hash, &key, &value); )
      {
        num_items++;

        if (strcmp((const char *)key, (const char *)value) != 0)
          SSH_ERROR("Found invalid value");
      }

    if (num_items != 5)
      SSH_ERROR("Enumeration did not find all items");
  }

  return errors;
}

int
main(int argc, char *argv[])
{
  SshHttpKvHash hash;
  int errors = 0;

  hash = ssh_http_kvhash_create(TRUE);
  errors += test(hash, TRUE);
  ssh_http_kvhash_destroy(hash);

  hash = ssh_http_kvhash_create(FALSE);
  errors += test(hash, FALSE);
  ssh_http_kvhash_destroy(hash);
  ssh_util_uninit();
  return errors;
}
