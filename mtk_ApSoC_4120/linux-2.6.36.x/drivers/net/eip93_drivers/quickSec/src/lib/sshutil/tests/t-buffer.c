/*

t-buffer.c

Author: Tatu Ylonen <ylo@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
                   All rights reserved

Created: Thu Oct 24 20:38:23 1996 ylo
Last modified: 22:14 Mar 11 2001 kivinen

*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshbufaux.h"

int main()
{
  int pass, subpass, i;
  unsigned char data[1024];
  SshBufferStruct b;
  SshBuffer bufferp;
  char *s, *s2;
  unsigned int len, origlen;
  size_t len2;





  for (pass = 0; pass < 20; pass++)
    {
      ssh_buffer_init(&b);

      for (subpass = 0; subpass < 10; subpass++)
        {
          ssh_buffer_clear(&b);
          s = "this is test data.";
          len = strlen(s) + 1;
          memcpy(data, s, len);
          for (i = 0; i < 2000; i++)
            ssh_buffer_append(&b, data, len);
          origlen = ssh_buffer_len(&b);
          for (i = 0; i < 1000; i++)
            {
              if (memcmp(ssh_buffer_ptr(&b), s, len) != 0)
                {
                  printf("ssh_buffer_ptr fails\n");
                  exit(1);
                }
              memset(ssh_buffer_ptr(&b), 'B', len);
              ssh_buffer_consume(&b, len);
            }
          if (ssh_buffer_len(&b) * 2 != origlen)
            {
              printf("ssh_buffer_len * 2 test fails\n");
              exit(1);
            }
          for (i = 0; i < len; i++)
            {
              if (ssh_buffer_len(&b) != origlen / 2 - i ||
                  memcmp(ssh_buffer_ptr(&b), s, len) != 0)
                {
                  printf("ssh_buffer_consume_end test fails\n");
                  exit(1);
                }
              ssh_buffer_consume_end(&b, 1);
            }
          memset(data, 'A', sizeof(data));
#if 0
          ssh_buffer_get(&b, data, sizeof(data));
          for (cp = data; cp + len < data + sizeof(data); cp += len)
            if (memcmp(cp, s, len) != 0)
              {
                printf("buffer_get test fails\n");
                exit(1);
              }
#endif
          ssh_buffer_clear(&b);
          if (ssh_buffer_len(&b) != 0)
            {
              printf("ssh_buffer_clear test fails\n");
              exit(1);
            }
        }
      ssh_buffer_uninit(&b);
    }

  for (pass = 0; pass < 100; pass++)
    {
      ssh_buffer_init(&b);

      for (i = 0; i < 1000; i++)
        {



          ssh_bufaux_put_char(&b, i);
          ssh_bufaux_put_uint32_string(&b, s, len);
        }

      for (i = 0; i < 1000; i++)
        {









          if (ssh_bufaux_get_char(&b) != i % 256)
            {
              printf("ssh_bufaux_get_char failed\n");
              exit(1);
            }
          s2 = (char *)ssh_bufaux_get_uint32_string(&b, &len2);
          if (strcmp(s, s2) != 0 || len2 != len)
            {
              printf("ssh_bufaux_get_uint32_string failed\n");
              exit(1);
            }
          ssh_xfree(s2);
        }
      if (ssh_buffer_len(&b) != 0)
        {
          printf("buffer not empty at end\n");
          exit(1);
        }
      ssh_buffer_uninit(&b);

      bufferp = ssh_buffer_allocate();
      ssh_buffer_free(bufferp);
    }

  ssh_util_uninit();
  return 0;
}
