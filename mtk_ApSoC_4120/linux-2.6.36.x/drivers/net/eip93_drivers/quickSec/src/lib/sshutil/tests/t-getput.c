/*

t-getput.c

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
                   All rights reserved

Test program for the SSH_GET_* and SSH_PUT_* macros.

*/

#include "sshincludes.h"
#include "sshtimemeasure.h"
#include "sshgetput.h"

typedef struct TestRec {
  unsigned char w16a[2];
  unsigned char w16b[2];
  unsigned char w24[3];
  unsigned char w32[4];
  unsigned char w40[5];
  unsigned char w64[8];
} *Test;

int main(int argc, char **argv)
{
  Test t;
  int i, j;
  SshUInt64 k;
  SshUInt32 a;
  SshTimeMeasure timer;
  unsigned char buf[10];

  timer = ssh_time_measure_allocate();
  ssh_time_measure_start(timer);
  t = ssh_xcalloc(500, sizeof(struct TestRec));
  for (j = 0; j < 1000; j++)
    {
      for (i = 0; i < 500; i++)
        {
          a = i + (j << 10);
          SSH_PUT_16BIT(t[i].w16a, a);
          SSH_PUT_16BIT(t[i].w16b, a);
          SSH_PUT_24BIT(t[i].w24, a);
          SSH_PUT_32BIT(t[i].w32, a);
          SSH_PUT_40BIT(t[i].w40, a);
          SSH_PUT_64BIT(t[i].w64, a);
        }
      for (i = 0; i < 500; i++)
        {
          a = i + (j << 10);
          if (SSH_GET_16BIT(t[i].w16a) != (a & 0xffff))
            ssh_fatal("SSH_GET_16BIT failed");
          if (SSH_GET_16BIT(t[i].w16b) != (a & 0xffff))
            ssh_fatal("SSH_GET_16BIT failed");
          if (SSH_GET_24BIT(t[i].w24) != (a & 0xffffff))
            ssh_fatal("SSH_GET_24BIT failed");
          if (SSH_GET_32BIT(t[i].w32) != a)
            ssh_fatal("SSH_GET_32BIT failed");
          if (SSH_GET_40BIT(t[i].w40) != a)
            ssh_fatal("SSH_GET_40BIT failed");
          if (SSH_GET_64BIT(t[i].w64) != a)
            ssh_fatal("SSH_GET_64BIT failed");
        }
      for (i = 0; i < 500; i++)
        {
          a = i + (j << 10);
          SSH_PUT_16BIT_LSB_FIRST(t[i].w16a, a);
          SSH_PUT_16BIT_LSB_FIRST(t[i].w16b, a);
          SSH_PUT_24BIT_LSB_FIRST(t[i].w24, a);
          SSH_PUT_32BIT_LSB_FIRST(t[i].w32, a);
          SSH_PUT_40BIT_LSB_FIRST(t[i].w40, a);
          SSH_PUT_64BIT_LSB_FIRST(t[i].w64, a);
        }
      for (i = 0; i < 500; i++)
        {
          a = i + (j << 10);
          if (SSH_GET_16BIT_LSB_FIRST(t[i].w16a) != (a & 0xffff))
            ssh_fatal("SSH_GET_16BIT_LSB_FIRST failed");
          if (SSH_GET_16BIT_LSB_FIRST(t[i].w16b) != (a & 0xffff))
            ssh_fatal("SSH_GET_16BIT_LSB_FIRST failed");
          if (SSH_GET_24BIT_LSB_FIRST(t[i].w24) != (a & 0xffffff))
            ssh_fatal("SSH_GET_24BIT_LSB_FIRST failed");
          if (SSH_GET_32BIT_LSB_FIRST(t[i].w32) != a)
            ssh_fatal("SSH_GET_32BIT_LSB_FIRST failed");
          if (SSH_GET_40BIT_LSB_FIRST(t[i].w40) != a)
            ssh_fatal("SSH_GET_40BIT_LSB_FIRST failed");
          if (SSH_GET_64BIT_LSB_FIRST(t[i].w64) != a)
            ssh_fatal("SSH_GET_64BIT_LSB_FIRST failed");
        }
      for (i = 0; i < 500; i++)
        {
          a = i + (j << 10);
          SSH_PUT_16BIT(t[i].w16a, a);
          SSH_PUT_16BIT(t[i].w16b, a);
          SSH_PUT_24BIT(t[i].w24, a);
          SSH_PUT_32BIT(t[i].w32, a);
          SSH_PUT_40BIT(t[i].w40, a);
          SSH_PUT_64BIT(t[i].w64, a);
        }
      for (i = 0; i < 500; i++)
        {
          a = i + (j << 10);
          if (t[i].w16a[0] != ((a & 0xff00) >> 8) ||
              t[i].w16a[1] != (a & 0xff))
            ssh_fatal("SSH_PUT_16BIT failed");
          if (t[i].w16b[0] != ((a & 0xff00) >> 8) ||
              t[i].w16b[1] != (a & 0xff))
            ssh_fatal("SSH_PUT_16BIT failed");
          if (t[i].w24[0] != ((a & 0xff0000) >> 16) ||
              t[i].w24[1] != ((a & 0xff00) >> 8) ||
              t[i].w24[2] != (a & 0xff))
            ssh_fatal("SSH_PUT_24BIT failed");
          if (t[i].w32[0] != ((a & 0xff000000) >> 24) ||
              t[i].w32[1] != ((a & 0xff0000) >> 16) ||
              t[i].w32[2] != ((a & 0xff00) >> 8) ||
              t[i].w32[3] != (a & 0xff))
            ssh_fatal("SSH_PUT_32BIT failed");

          if (t[i].w40[0] != 0 ||
              t[i].w40[1] != ((a & 0xff000000) >> 24) ||
              t[i].w40[2] != ((a & 0xff0000) >> 16) ||
              t[i].w40[3] != ((a & 0xff00) >> 8) ||
              t[i].w40[4] != (a & 0xff))
            ssh_fatal("SSH_PUT_40BIT failed");
          if (t[i].w64[0] != 0 || t[i].w64[1] != 0 ||
              t[i].w64[2] != 0 || t[i].w64[3] != 0 ||
              t[i].w64[4] != ((a & 0xff000000) >> 24) ||
              t[i].w64[5] != ((a & 0xff0000) >> 16) ||
              t[i].w64[6] != ((a & 0xff00) >> 8) ||
              t[i].w64[7] != (a & 0xff))
            ssh_fatal("SSH_PUT_64BIT failed");
        }
    }

#define BUFTEST(x,f,v,s) \
  memset(buf, (f), 10); \
  x(buf + 1, (v)); \
  if (memcmp(buf, (s), 10) != 0) \
    ssh_fatal(#x " failed");

  BUFTEST(SSH_PUT_16BIT, 0, 0x0000,
          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
  BUFTEST(SSH_PUT_16BIT, 0, 0xffff,
          "\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00");
  BUFTEST(SSH_PUT_16BIT, 0, 0x1234,
          "\x00\x12\x34\x00\x00\x00\x00\x00\x00\x00");

  BUFTEST(SSH_PUT_16BIT, 0xff, 0x0000,
          "\xff\x00\x00\xff\xff\xff\xff\xff\xff\xff");
  BUFTEST(SSH_PUT_16BIT, 0xff, 0xffff,
          "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff");
  BUFTEST(SSH_PUT_16BIT, 0xff, 0x1234,
          "\xff\x12\x34\xff\xff\xff\xff\xff\xff\xff");

  BUFTEST(SSH_PUT_16BIT_LSB_FIRST, 0, 0x0000,
          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
  BUFTEST(SSH_PUT_16BIT_LSB_FIRST, 0, 0xffffU,
          "\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00");
  BUFTEST(SSH_PUT_16BIT_LSB_FIRST, 0, 0x1234U,
          "\x00\x34\x12\x00\x00\x00\x00\x00\x00\x00");

  BUFTEST(SSH_PUT_16BIT_LSB_FIRST, 0xff, 0x0000,
          "\xff\x00\x00\xff\xff\xff\xff\xff\xff\xff");
  BUFTEST(SSH_PUT_16BIT_LSB_FIRST, 0xff, 0xffffU,
          "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff");
  BUFTEST(SSH_PUT_16BIT_LSB_FIRST, 0xff, 0x1234U,
          "\xff\x34\x12\xff\xff\xff\xff\xff\xff\xff");

  BUFTEST(SSH_PUT_24BIT, 0, 0x00000000U,
          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
  BUFTEST(SSH_PUT_24BIT, 0, 0xffffffU,
          "\x00\xff\xff\xff\x00\x00\x00\x00\x00\x00");
  BUFTEST(SSH_PUT_24BIT, 0, 0x123456U,
          "\x00\x12\x34\x56\x00\x00\x00\x00\x00\x00");

  BUFTEST(SSH_PUT_24BIT, 0xff, 0x000000U,
          "\xff\x00\x00\x00\xff\xff\xff\xff\xff\xff");
  BUFTEST(SSH_PUT_24BIT, 0xff, 0xffffffU,
          "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff");
  BUFTEST(SSH_PUT_24BIT, 0xff, 0x123456U,
          "\xff\x12\x34\x56\xff\xff\xff\xff\xff\xff");

  BUFTEST(SSH_PUT_24BIT_LSB_FIRST, 0, 0x000000U,
          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
  BUFTEST(SSH_PUT_24BIT_LSB_FIRST, 0, 0xffffffU,
          "\x00\xff\xff\xff\x00\x00\x00\x00\x00\x00");
  BUFTEST(SSH_PUT_24BIT_LSB_FIRST, 0, 0x123456U,
          "\x00\x56\x34\x12\x00\x00\x00\x00\x00\x00");

  BUFTEST(SSH_PUT_24BIT_LSB_FIRST, 0xff, 0x000000U,
          "\xff\x00\x00\x00\xff\xff\xff\xff\xff\xff");
  BUFTEST(SSH_PUT_24BIT_LSB_FIRST, 0xff, 0xffffffU,
          "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff");
  BUFTEST(SSH_PUT_24BIT_LSB_FIRST, 0xff, 0x123456U,
          "\xff\x56\x34\x12\xff\xff\xff\xff\xff\xff");

  BUFTEST(SSH_PUT_32BIT, 0, 0x00000000U,
          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
  BUFTEST(SSH_PUT_32BIT, 0, 0xffffffffU,
          "\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00");
  BUFTEST(SSH_PUT_32BIT, 0, 0x12345678U,
          "\x00\x12\x34\x56\x78\x00\x00\x00\x00\x00");

  BUFTEST(SSH_PUT_32BIT, 0xff, 0x00000000U,
          "\xff\x00\x00\x00\x00\xff\xff\xff\xff\xff");
  BUFTEST(SSH_PUT_32BIT, 0xff, 0xffffffffU,
          "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff");
  BUFTEST(SSH_PUT_32BIT, 0xff, 0x12345678U,
          "\xff\x12\x34\x56\x78\xff\xff\xff\xff\xff");

  BUFTEST(SSH_PUT_32BIT_LSB_FIRST, 0, 0x00000000U,
          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
  BUFTEST(SSH_PUT_32BIT_LSB_FIRST, 0, 0xffffffffU,
          "\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00");
  BUFTEST(SSH_PUT_32BIT_LSB_FIRST, 0, 0x12345678U,
          "\x00\x78\x56\x34\x12\x00\x00\x00\x00\x00");

  BUFTEST(SSH_PUT_32BIT_LSB_FIRST, 0xff, 0x00000000U,
          "\xff\x00\x00\x00\x00\xff\xff\xff\xff\xff");
  BUFTEST(SSH_PUT_32BIT_LSB_FIRST, 0xff, 0xffffffffU,
          "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff");
  BUFTEST(SSH_PUT_32BIT_LSB_FIRST, 0xff, 0x12345678U,
          "\xff\x78\x56\x34\x12\xff\xff\xff\xff\xff");

#ifdef SSHUINT64_IS_64BITS
  BUFTEST(SSH_PUT_40BIT, 0, SSH_C64(0x0000000000),
          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
  BUFTEST(SSH_PUT_40BIT, 0, SSH_C64(0xffffffffff),
          "\x00\xff\xff\xff\xff\xff\x00\x00\x00\x00");
  BUFTEST(SSH_PUT_40BIT, 0, SSH_C64(0x123456789a),
          "\x00\x12\x34\x56\x78\x9a\x00\x00\x00\x00");

  BUFTEST(SSH_PUT_40BIT, 0xff, SSH_C64(0x0000000000),
          "\xff\x00\x00\x00\x00\x00\xff\xff\xff\xff");
  BUFTEST(SSH_PUT_40BIT, 0xff, SSH_C64(0xffffffffff),
          "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff");
  BUFTEST(SSH_PUT_40BIT, 0xff, SSH_C64(0x123456789a),
          "\xff\x12\x34\x56\x78\x9a\xff\xff\xff\xff");

  BUFTEST(SSH_PUT_40BIT_LSB_FIRST, 0, SSH_C64(0x0000000000),
          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
  BUFTEST(SSH_PUT_40BIT_LSB_FIRST, 0, SSH_C64(0xffffffffff),
          "\x00\xff\xff\xff\xff\xff\x00\x00\x00\x00");
  BUFTEST(SSH_PUT_40BIT_LSB_FIRST, 0, SSH_C64(0x123456789a),
          "\x00\x9a\x78\x56\x34\x12\x00\x00\x00\x00");

  BUFTEST(SSH_PUT_40BIT_LSB_FIRST, 0xff, SSH_C64(0x0000000000),
          "\xff\x00\x00\x00\x00\x00\xff\xff\xff\xff");
  BUFTEST(SSH_PUT_40BIT_LSB_FIRST, 0xff, SSH_C64(0xffffffffff),
          "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff");
  BUFTEST(SSH_PUT_40BIT_LSB_FIRST, 0xff, SSH_C64(0x123456789a),
          "\xff\x9a\x78\x56\x34\x12\xff\xff\xff\xff");

  BUFTEST(SSH_PUT_64BIT, 0, SSH_C64(0x0000000000000000),
          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
  BUFTEST(SSH_PUT_64BIT, 0, SSH_C64(0xffffffffffffffff),
          "\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00");
  BUFTEST(SSH_PUT_64BIT, 0, SSH_C64(0x123456789abcdef0),
          "\x00\x12\x34\x56\x78\x9a\xbc\xde\xf0\x00");

  BUFTEST(SSH_PUT_64BIT, 0xff, SSH_C64(0x0000000000000000),
          "\xff\x00\x00\x00\x00\x00\x00\x00\x00\xff");
  BUFTEST(SSH_PUT_64BIT, 0xff, SSH_C64(0xffffffffffffffff),
          "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff");
  BUFTEST(SSH_PUT_64BIT, 0xff, SSH_C64(0x123456789abcdef0),
          "\xff\x12\x34\x56\x78\x9a\xbc\xde\xf0\xff");

  BUFTEST(SSH_PUT_64BIT_LSB_FIRST, 0, SSH_C64(0x0000000000000000),
          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
  BUFTEST(SSH_PUT_64BIT_LSB_FIRST, 0, SSH_C64(0xffffffffffffffff),
          "\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00");
  BUFTEST(SSH_PUT_64BIT_LSB_FIRST, 0, SSH_C64(0x123456789abcdef0),
          "\x00\xf0\xde\xbc\x9a\x78\x56\x34\x12\x00");

  BUFTEST(SSH_PUT_64BIT_LSB_FIRST, 0xff, SSH_C64(0x0000000000000000),
          "\xff\x00\x00\x00\x00\x00\x00\x00\x00\xff");
  BUFTEST(SSH_PUT_64BIT_LSB_FIRST, 0xff, SSH_C64(0xffffffffffffffff),
          "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff");
  BUFTEST(SSH_PUT_64BIT_LSB_FIRST, 0xff, SSH_C64(0x123456789abcdef0),
          "\xff\xf0\xde\xbc\x9a\x78\x56\x34\x12\xff");
#endif /* SSHUINT64_IS_64BITS */

  ssh_time_measure_stop(timer);
  printf("Time = %g secs\n",
         (double) ssh_time_measure_get(timer,
                                       SSH_TIME_GRANULARITY_SECOND));
#define TEST(x)                                                         \
  ssh_time_measure_reset(timer);                                        \
  ssh_time_measure_start(timer);                                        \
  for (j = 0; j < 10000; j++)                                           \
    for (i = 0; i < 500; i++)                                           \
      x;                                                                \
  ssh_time_measure_stop(timer);                                         \
  printf("Time " #x " = %g usecs/call\n",                               \
         (double) ssh_time_measure_get(timer,                           \
                                       SSH_TIME_GRANULARITY_SECOND) *   \
         1000000 / (500 * 10000));

  k = 1;
  TEST(SSH_PUT_16BIT(t[i].w16a, k));
  TEST(k += SSH_GET_16BIT(t[i].w16a));
  TEST(SSH_PUT_24BIT(t[i].w24, k));
  TEST(k += SSH_GET_24BIT(t[i].w24));
  TEST(SSH_PUT_32BIT(t[i].w32, k));
  TEST(k += SSH_GET_32BIT(t[i].w32));
  TEST(SSH_PUT_40BIT(t[i].w40, k));
  TEST(k += SSH_GET_40BIT(t[i].w40));
  TEST(SSH_PUT_64BIT(t[i].w64, k));
  TEST(k += SSH_GET_64BIT(t[i].w64));

  SSH_PUT_16BIT(t[0].w16a, (unsigned char) 0);
  SSH_PUT_24BIT(t[0].w24, (unsigned char) 0);
  SSH_PUT_32BIT(t[0].w32, (unsigned char) 0);
  SSH_PUT_40BIT(t[0].w40, (unsigned char) 0);
  SSH_PUT_64BIT(t[0].w64, (unsigned char) 0);

  SSH_PUT_16BIT(t[0].w16a, (SshUInt16) 0);
  SSH_PUT_24BIT(t[0].w24, (SshUInt16) 0);
  SSH_PUT_32BIT(t[0].w32, (SshUInt16) 0);
  SSH_PUT_40BIT(t[0].w40, (SshUInt16) 0);
  SSH_PUT_64BIT(t[0].w64, (SshUInt16) 0);

  SSH_PUT_16BIT(t[0].w16a, (SshUInt32) 0);
  SSH_PUT_24BIT(t[0].w24, (SshUInt32) 0);
  SSH_PUT_32BIT(t[0].w32, (SshUInt32) 0);
  SSH_PUT_40BIT(t[0].w40, (SshUInt32) 0);
  SSH_PUT_64BIT(t[0].w64, (SshUInt32) 0);

  SSH_PUT_16BIT(t[0].w16a, (SshUInt64) 0);
  SSH_PUT_24BIT(t[0].w24, (SshUInt64) 0);
  SSH_PUT_32BIT(t[0].w32, (SshUInt64) 0);
  SSH_PUT_40BIT(t[0].w40, (SshUInt64) 0);
  SSH_PUT_64BIT(t[0].w64, (SshUInt64) 0);

  printf("k = %ld\n", (unsigned long) k);
  ssh_time_measure_free(timer);
  ssh_xfree(t);
  ssh_util_uninit();
  return 0;
}
