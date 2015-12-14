/*
 *
 * @FILENAME@
 *
 * Author: Markku Rossi <mtr@ssh.fi>
 *
 *  Copyright:
 *          Copyright (c) 2002, 2003 SFNT Finland Oy.
 *               All rights reserved.
 *
 * What is this file for?
 *
 */

#include "sshincludes.h"
#include "zlib.h"
#include "zutil.h"
#include "sshcrypt.h"

#define SSH_DEBUG_MODULE "t-zlib"

#define BUFSIZE 65535

int
main(int argc, char *argv[])
{
  unsigned char *buf = ssh_xmalloc(BUFSIZE);
  unsigned char *buf2 = ssh_xmalloc(BUFSIZE);
  unsigned char *buf3 = ssh_xmalloc(BUFSIZE);
  int buf2len;
  int i;
  int status;
  z_stream s_deflate;
  z_stream s_inflate;

  for (i = 0; i < BUFSIZE; i++)
#if 0
    buf[i] = (unsigned char) ssh_random_get_byte();
#else
    buf[i] = (unsigned char) i;
#endif

  memset(&s_deflate, 0, sizeof(s_deflate));
  status = deflateInit2_(&s_deflate, Z_DEFAULT_COMPRESSION,
                         Z_DEFLATED, -11, DEF_MEM_LEVEL,
                         Z_DEFAULT_STRATEGY, ZLIB_VERSION,
                         sizeof(z_stream));
  SSH_ASSERT(status == Z_OK);

  memset(&s_inflate, 0, sizeof(s_inflate));
  status = inflateInit2_(&s_inflate,  -15, ZLIB_VERSION,
                         sizeof(z_stream));
  SSH_ASSERT(status == Z_OK);

  for (i = 0; i < BUFSIZE; i++)
    {
      s_deflate.next_in = buf;
      s_deflate.avail_in = i;
      s_deflate.next_out = buf2;
      s_deflate.avail_out = BUFSIZE;

      status = deflate(&s_deflate, Z_FINISH);
      if (status != Z_STREAM_END)
        ssh_fatal("status=%d", status);

      buf2len = s_deflate.total_out;
      status = deflateReset(&s_deflate);
      SSH_ASSERT(status == Z_OK);

      s_inflate.next_in = buf2;
      s_inflate.avail_in = buf2len;
      s_inflate.next_out = buf3;
      s_inflate.avail_out = BUFSIZE;

      status = inflate(&s_inflate, Z_FINISH);
      if (status != Z_STREAM_END)
        ssh_warning("status=%d", status);

      if (buf2len < i || 1)
        printf("inlen=%d, outlen=%d, inlen=%lu, %.2f\n", i, buf2len,
               (unsigned long) s_inflate.total_out,
               (double) buf2len / i);
#if 0
      SSH_ASSERT(i == s_inflate.total_out);
#endif
      if (memcmp(buf, buf3, i) != 0)
        ssh_warning("output differs");

      status = inflateReset(&s_inflate);
      SSH_ASSERT(status == Z_OK);
    }

  return 0;
}
