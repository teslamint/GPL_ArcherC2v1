/*

t-esnprintf.c

Author: Tatu Ylonen <ylo@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
                   All rights reserved

Created: Thu Oct 24 22:38:16 1996 ylo
Last modified: 14:28 Apr 28 2005 kivinen

*/

#include "sshincludes.h"
#include "stdarg.h"

void test(const char *expect, const char *fmt, ...)
{
  va_list va;
  char buf[1024];

  va_start(va, fmt);
  ssh_vsnprintf(buf, sizeof(buf), fmt, va);
  va_end(va);

  if (strcmp(expect, buf) != 0)
    {
      printf("ssh_vsnprintf test failed, "
             "format '%s', expected '%s', got '%s'\n",
             fmt, expect, buf);
      ssh_util_uninit();
      exit(1);
    }
}

Boolean testpad(unsigned char *buf)
{
  int i;
  for (i = 0; i < 10; i++)
    if (buf[i] != 10+i)
      return FALSE;
  return TRUE;
}

int main(int ac, char **av)
{
  char buf[1024];
  unsigned char buf2[30];
  int pass, status = 0, i;

  for (pass = 0; pass < 100; pass++)
    {
      ssh_snprintf(buf, sizeof(buf), "a%dl", 7);
      if (strcmp(buf, "a7l") != 0)
        {
          printf("trivial ssh_snprintf test failed\n");
          ssh_util_uninit();
          exit(1);
        }

      test("-124", "%d", -124);
      test(" -124", "%5d", -124);
      test("-124 ", "%-5d", -124);
      test("00124", "%05d", 124);
      test("1234567", "%5ld", 1234567L);

      test("-124", "%lld", SSH_S64(-124));
      test(" -124", "%5lld", SSH_S64(-124));
      test("-124 ", "%-5lld", SSH_S64(-124));
      test("00124", "%05lld", SSH_C64(124));
      test("1234567", "%5lld", SSH_C64(1234567));
#ifdef HAVE_LONG_LONG
      test("1234567890123456789", "%lld", SSH_C64(1234567890123456789));
#endif

      test("d", "%c", 100);
      test("64", "%x", 100);
      test("0A", "%02X", 10);
      test("0x64", "%#x", 100);
      test("0064", "%04x", 100);
      test("144", "%lo", 100L);

      test("d", "%llc", SSH_C64(100));
      test("64", "%llx", SSH_C64(100));
      test("0A", "%02llX", SSH_C64(10));
      test("0x64", "%#llx", SSH_C64(100));
      test("0064", "%04llx", SSH_C64(100));
      test("144", "%llo", SSH_C64(100));

      test("ab", "%.2s", "abcdef");
      test("abcdef", "%2s", "abcdef");
      test("    abc", "%*.*s", 7, 3, "abcdef");
      test("   ab", "%5.2s", "abcdef");
      test("ab   ", "%-5.2s", "abcdef");

      test("1.1", "%g", 1.1);
      test("-7.4", "%lg", (double)-7.4);

      test(" -1", "%3d", -1);
      test("-1 ", "%-3d", -1);
      test("-1 ", "%-03d", -1);
      test("-01", "%03d", -1);
    }

  for (i = 0; i < 10; i++)
    {
      buf2[i     ] = 10+i;
      buf2[20 + i] = 10+i;
    }

  ssh_snprintf((char *)(buf2+10), 10, "kukkuu%s", "RESET");
  if (strcmp((char *)(buf2+10), "kukkuuRESET") == 0 ||
      strlen((char *)(buf2+10)) != 9 || !testpad(buf2+0) || !testpad(buf2+20))
    {
      printf("buffer overrun detection failed 1\n");
      status++;
    }
  ssh_snprintf((char *)(buf2+10), 10, "kukkuu%07x", 10);
  if (strcmp((char *)(buf2+10), "kukkuu000000A") == 0 ||
      strlen((char *)(buf2+10)) != 9 || !testpad(buf2+0) || !testpad(buf2+20))
    {
      printf("buffer overrun detection failed 2\n");
      status++;
    }
  ssh_snprintf((char *)(buf2+10), 10, "kukkuu%7x", 10);
  if (strcmp((char *)(buf2+10), "kukkuu      A") == 0 ||
      strlen((char *)(buf2+10)) != 9 || !testpad(buf2+0) || !testpad(buf2+20))
    {
      printf("buffer overrun detection failed 3\n");
      status++;
    }
  ssh_snprintf((char *)(buf2+10), 10, "kukkuu%f", 3.141592);
  if (strcmp((char *)(buf2+10), "kukkuu3.141592") == 0 ||
      strlen((char *)(buf2+10)) != 9 || !testpad(buf2+0) || !testpad(buf2+20))
    {
      printf("buffer overrun detection failed 4\n");
      status++;
    }
  ssh_snprintf((char *)(buf2+10), 10, "kukkuu%g", 3.141592);
  if (strcmp((char *)(buf2+10), "kukkuu3.141592") == 0 ||
      strlen((char *)(buf2+10)) != 9 || !testpad(buf2+0) || !testpad(buf2+20))
    {
      printf("buffer overrun detection failed 5\n");
      status++;
    }
  ssh_snprintf((char *)(buf2+10), 10, "kukkuu%-7f", 3.141592);
  if (strcmp((char *)(buf2+10), "kukkuu3.141592") == 0 ||
      strlen((char *)(buf2+10)) != 9 || !testpad(buf2+0) || !testpad(buf2+20))
    {
      printf("buffer overrun detection failed 6\n");
      status++;
    }
  ssh_snprintf((char *)(buf2+10), 10, "kukkuu%-+7f", 3.141592);
  if (strcmp((char *)(buf2+10), "kukkuu+3.141592") == 0 ||
      strlen((char *)(buf2+10)) != 9 || !testpad(buf2+0) || !testpad(buf2+20))
    {
      printf("buffer overrun detection failed 7\n");
      status++;
    }
  ssh_snprintf((char *)(buf2+10), 10, "kuk%-+7f", -3.141592);
  if (strcmp((char *)(buf2+10), "kuk-3.141592") == 0 ||
      strlen((char *)(buf2+10)) != 9 || !testpad(buf2+0) || !testpad(buf2+20))
    {
      printf("buffer overrun detection failed 8\n");
      status++;
    }

  memset(buf, '-', 5); ssh_snprintf(buf, 5, "%d", 1);
  if (strcmp(buf, "1") != 0)
    { printf("Number test failed 1\n"); status++; }

  memset(buf, '-', 5); ssh_snprintf(buf, 5, "%d", 10);
  if (strcmp(buf, "10") != 0)
    { printf("Number test failed 2\n"); status++; }

  memset(buf, '-', 5); ssh_snprintf(buf, 5, "%d", 100);
  if (strcmp(buf, "100") != 0)
    { printf("Number test failed 3\n"); status++; }

  memset(buf, '-', 5); ssh_snprintf(buf, 5, "%d", 1000);
  if (strcmp(buf, "1000") != 0)
    { printf("Number test failed 4\n"); status++; }

  memset(buf, '-', 5); ssh_snprintf(buf, 4, "%d", 1000);
  if (strcmp(buf, "100") != 0)
    { printf("Number test failed 5\n"); status++; }

  memset(buf, '-', 5); ssh_snprintf(buf, 3, "%d", 1000);
  if (strcmp(buf, "10") != 0)
    { printf("Number test failed 6\n"); status++; }

  memset(buf, '-', 5); ssh_snprintf(buf, 2, "%d", 1000);
  if (strcmp(buf, "1") != 0)
    { printf("Number test failed 7\n"); status++; }

  memset(buf, '-', 5); ssh_snprintf(buf, 1, "%d", 1000);
  if (strcmp(buf, "") != 0)
    { printf("Number test failed 8\n"); status++; }

  memset(buf, '-', 5); ssh_snprintf(buf, 5, "%04d", 1);
  if (strcmp(buf, "0001") != 0)
    { printf("Number test failed 9\n"); status++; }

  memset(buf, '-', 5); ssh_snprintf(buf, 4, "%04d", 1);
  if (strcmp(buf, "000") != 0)
    { printf("Number test failed 10\n"); status++; }

  memset(buf, '-', 5); ssh_snprintf(buf, 3, "%04d", 1);
  if (strcmp(buf, "00") != 0)
    { printf("Number test failed 11\n"); status++; }

  memset(buf, '-', 5); ssh_snprintf(buf, 2, "%04d", 1);
  if (strcmp(buf, "0") != 0)
    { printf("Number test failed 12\n"); status++; }

  memset(buf, '-', 5); ssh_snprintf(buf, 1, "%04d", 1);
  if (strcmp(buf, "") != 0)
    { printf("Number test failed 13\n"); status++; }

  memset(buf, '-', 10); ssh_snprintf(buf, 5, "%02d:%02d:%02d", 23, 1, 1);
  if (strcmp(buf, "23:0") != 0)
    {
      printf("Number test failed 14, should return 23:0, returns %s\n", buf);
      status++;
    }

  memset(buf, '-', 5); ssh_snprintf(buf, 5, "%lld", SSH_C64(1));
  if (strcmp(buf, "1") != 0)
    { printf("Number test failed 1\n"); status++; }

  memset(buf, '-', 5); ssh_snprintf(buf, 5, "%lld", SSH_C64(10));
  if (strcmp(buf, "10") != 0)
    { printf("Number test failed 2\n"); status++; }

  memset(buf, '-', 5); ssh_snprintf(buf, 5, "%lld", SSH_C64(100));
  if (strcmp(buf, "100") != 0)
    { printf("Number test failed 3\n"); status++; }

  memset(buf, '-', 5); ssh_snprintf(buf, 5, "%lld", SSH_C64(1000));
  if (strcmp(buf, "1000") != 0)
    { printf("Number test failed 4\n"); status++; }

  memset(buf, '-', 5); ssh_snprintf(buf, 4, "%lld", SSH_C64(1000));
  if (strcmp(buf, "100") != 0)
    { printf("Number test failed 5\n"); status++; }

  memset(buf, '-', 5); ssh_snprintf(buf, 3, "%lld", SSH_C64(1000));
  if (strcmp(buf, "10") != 0)
    { printf("Number test failed 6\n"); status++; }

  memset(buf, '-', 5); ssh_snprintf(buf, 2, "%lld", SSH_C64(1000));
  if (strcmp(buf, "1") != 0)
    { printf("Number test failed 7\n"); status++; }

  memset(buf, '-', 5); ssh_snprintf(buf, 1, "%lld", SSH_C64(1000));
  if (strcmp(buf, "") != 0)
    { printf("Number test failed 8\n"); status++; }

  memset(buf, '-', 5); ssh_snprintf(buf, 5, "%04lld", SSH_C64(1));
  if (strcmp(buf, "0001") != 0)
    { printf("Number test failed 9\n"); status++; }

  memset(buf, '-', 5); ssh_snprintf(buf, 4, "%04lld", SSH_C64(1));
  if (strcmp(buf, "000") != 0)
    { printf("Number test failed 10\n"); status++; }

  memset(buf, '-', 5); ssh_snprintf(buf, 3, "%04lld", SSH_C64(1));
  if (strcmp(buf, "00") != 0)
    { printf("Number test failed 11\n"); status++; }

  memset(buf, '-', 5); ssh_snprintf(buf, 2, "%04lld", SSH_C64(1));
  if (strcmp(buf, "0") != 0)
    { printf("Number test failed 12\n"); status++; }

  memset(buf, '-', 5); ssh_snprintf(buf, 1, "%04lld", SSH_C64(1));
  if (strcmp(buf, "") != 0)
    { printf("Number test failed 13\n"); status++; }

  memset(buf, '-', 10);
  ssh_snprintf(buf, 5, "%02lld:%02lld:%02lld",
                  SSH_C64(23), SSH_C64(1), SSH_C64(1));

  if (strcmp(buf, "23:0") != 0)
    {
      printf("Number test failed 14, should return 23:0, returns %s\n", buf);
      status++;
    }

  memset(buf, '-', 10); ssh_snprintf(buf, 10, "%3.0f", 9.999999);
  if (strcmp(buf, " 10") != 0)
    {
      printf("Number test failed 15, should return / 10/, returns /%s/\n",
             buf);
      status++;
    }

  memset(buf, '-', 10); ssh_snprintf(buf, 4, "%3.0f", 9.999999);
  if (strcmp(buf, " 10") != 0)
    {
      printf("Number test failed 16, should return / 10/, returns /%s/\n",
             buf);
      status++;
    }

  ssh_util_uninit();
  return status;
}
