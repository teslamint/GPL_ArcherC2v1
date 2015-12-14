/*

  t-eprintf.c

  Author: Antti Huima <huima@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All rights reserved.

  Created Wed Oct 13 15:19:02 1999.

  */

#include "sshincludes.h"

int render_string(char *buf, int buf_size, int precision, void *datum)
{
  char *str = (char *)datum;
  int l = strlen(str);
  if (l > buf_size) l = buf_size;
  if (precision >= 0)
    if (l > precision) l = precision;
  memcpy(buf, str, l);
  return l;
}

static void test(const char *expect, const char *fmt, ...)
{
  va_list va;
  char buf[1024];

  va_start(va, fmt);
  ssh_vsnprintf(buf, sizeof(buf), fmt, va);
  va_end(va);

  if (strcmp(expect, buf) != 0)
    {
      printf("eprintf test failed, format '%s', expected '%s', got '%s'\n",
             fmt, expect, buf);
      exit(1);
    }
}

static Boolean testpad(unsigned char *buf)
{
  int i;
  for (i = 0; i < 10; i++)
    if (buf[i] != 10+i)
      return FALSE;
  return TRUE;
}

static int snprintf_test(void)
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
          exit(1);
        }

      test("-124", "%d", -124);
      test(" -124", "%5d", -124);
      test("-124 ", "%-5d", -124);
      test("00124", "%05d", 124);
      test("1234567", "%5ld", 1234567L);

      test("d", "%c", 100);
      test("64", "%x", 100);
      test("0A", "%02X", 10);
      test("0x64", "%#x", 100);
      test("0064", "%04x", 100);
      test("144", "%lo", 100L);

      test("ab", "%.2s", "abcdef");
      test("abcdef", "%2s", "abcdef");
      test("    abc", "%*.*s", 7, 3, "abcdef");
      test("   ab", "%5.2s", "abcdef");
      test("ab   ", "%-5.2s", "abcdef");

      test("1.1", "%g", 1.1);
      test("-7.4", "%lg", (double)-7.4);
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
  return status;
}


int main(int argc, char **argv)
{
  int rv;

  test("foobar", "%@", render_string, "foobar");
  test("123456    ", "%-10@", render_string, "123456");
  test("    123456", "%10@", render_string, "123456");
  test("123", "%.3@", render_string, "123456");
  test("       123", "%10.3@", render_string, "123456");
  test("123       ", "%-10.3@", render_string, "123456");

  rv = snprintf_test();
  ssh_util_uninit();
  return rv;
}
