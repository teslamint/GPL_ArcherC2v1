/*

t-snprintf.c

Author: Tatu Ylonen <ylo@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
                   All rights reserved

Created: Thu Oct 24 22:38:16 1996 ylo
Last modified: 13:27 Jan 22 2009 kivinen

*/

#include "sshincludes.h"
#include "stdarg.h"

void test(const char *expect, const char *fmt, ...)
{
  va_list va;
  char buf[1024];
  int ret;

  va_start(va, fmt);
  ret = ssh_vsnprintf(buf, sizeof(buf), fmt, va);
  va_end(va);

  if (strlen(expect) != ret)
    {
      printf("ssh_snprintf test failed, return len %d, should be %d\n",
             ret, strlen(expect));
      exit(1);
    }

  if (strcmp(expect, buf) != 0)
    {
      printf("ssh_snprintf test failed, format '%s', "
             "expected '%s', got '%s'\n",
             fmt, expect, buf);
      exit(1);
    }
}

#define EXTDATA "some text only."


static int render_prec(unsigned char *buf, int buf_size,
		       int precision, void *datum)
{
  int len;

  if (strlen(EXTDATA) != precision)
    printf("ssh_snprintf test failed: extension format precision %d != %d\n",
           precision, strlen(EXTDATA));

  len = ssh_snprintf(buf, buf_size, "%s", (const unsigned char *)datum);
  return len < strlen(datum) ? (buf_size + 1) : len;
}

static int render(unsigned char *buf, int buf_size,
		  int precision, void *datum)
{
  int len ;

  len = ssh_snprintf(buf, buf_size, "%s", (const unsigned char *)datum);
  return len < strlen((const char *)datum) ? (buf_size + 1) : len;
}


Boolean testext(void)
{
  unsigned char buf0[8];
  unsigned char buf1[16];
  unsigned char buf2[1 + sizeof(EXTDATA)];
  int len, rv = TRUE;

  /* no fit; expect len == sizeof(buf)-1 */
  len = ssh_snprintf(buf0, sizeof(buf0),
                     "%.*@", strlen(EXTDATA), render, EXTDATA);
  if (len != sizeof(buf0)-1)
    {
      ssh_warning("ssh_snprintf: unexpected length returned (1).");
      rv = FALSE;
    }

  len = ssh_snprintf(buf1, sizeof(buf1),
                     "%.*@", strlen(EXTDATA), render, EXTDATA);
  if (len != sizeof(buf1)-1)
    {
      ssh_warning("ssh_snprintf: unexpected length returned (2).");
      rv = FALSE;
    }

  len = ssh_snprintf(buf2, sizeof(buf2),
                     "%.*@", strlen(EXTDATA), render, EXTDATA);
  if (len != strlen(EXTDATA))
    {
      ssh_warning("ssh_snprintf: unexpected length returned (3).");
      rv = FALSE;
    }

  len = ssh_snprintf(buf0, sizeof(buf0),
                     "%.*@", strlen(EXTDATA), render_prec, EXTDATA);
  if (len != sizeof(buf0)-1)
    {
      ssh_warning("ssh_snprintf: unexpected length returned (2).");
      rv = FALSE;
    }
  len = ssh_snprintf(buf1, sizeof(buf1),
                     "%.*@", strlen(EXTDATA), render_prec, EXTDATA);
  if (len != sizeof(buf1)-1)
    {
      ssh_warning("ssh_snprintf: unexpected length returned (2).");
      rv = FALSE;
    }
  len = ssh_snprintf(buf2, sizeof(buf2),
                     "%.*@", strlen(EXTDATA), render_prec, EXTDATA);
  if (len != strlen(EXTDATA))
    {
      ssh_warning("ssh_snprintf: unexpected length returned (3).");
      rv = FALSE;
    }

  return rv;
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
  int ret;

  testext();
  for (pass = 0; pass < 100; pass++)
    {
      ssh_snprintf(buf, sizeof(buf), "a%dl", 7);
      if (strcmp(buf, "a7l") != 0)
        {
          printf("trivial ssh_snprintf test failed\n");
          exit(1);
        }

      test("-124", "%d", -124);
      test("+124", "%+d", 124);
      test(" 124", "% d", 124);
      test(" -124", "%5d", -124);
      test(" +124", "%+5d", 124);
      test("  124", "% 5d", 124);
      test("-124 ", "%-5d", -124);
      test("+124 ", "%+-5d", 124);
      test(" 124 ", "% -5d", 124);
      test("00124", "%05d", 124);
      test("  00124", "%7.5d", 124);
      test("1234567", "%5ld", 1234567L);

      test("d", "%c", 100);
      test("64", "%x", 100);
      test("0A", "%02X", 10);
      test("0x64", "%#x", 100);
      test("0064", "%04x", 100);
      test("144", "%lo", 100L);
      test("124", "%qd", SSH_C64(124));
      test("124", "%lld", SSH_C64(124));
      test("123456789012345", "%qd", SSH_C64(123456789012345));
      test("123456789012345", "%lld", SSH_C64(123456789012345));
      test("1234", "%zd", (size_t) 1234);
      test("123456789", "%zd", (size_t) 123456789);
#ifdef USERMODE_SIZEOF_SIZE_T
#if USERMODE_SIZEOF_SIZE_T >= 8
      test("12345678912345", "%zd", (size_t) SSH_C64(12345678912345));
#endif /* USERMODE_SIZEOF_SIZE_T >= 8 */
#endif /* USERMODE_SIZEOF_SIZE_T */

      test("12345678", "%p", (void *) 0x12345678U);
#ifdef USERMODE_SIZEOF_VOID_P
#if USERMODE_SIZEOF_VOID_P >= 8
      test("1234567890123456", "%p", (void *) SSH_C64(0x1234567890123456));
#endif /* USERMODE_SIZEOF_VOID_P >= 8 */
#endif /* USERMODE_SIZEOF_VOID_P */

      test("ab", "%.2s", "abcdef");
      test("abcdef", "%2s", "abcdef");
      test("    abc", "%*.*s", 7, 3, "abcdef");
      test("   ab", "%5.2s", "abcdef");
      test("ab   ", "%-5.2s", "abcdef");

      test("1.1", "%g", 1.1);
      test("1.100000", "%f", 1.1);
      test("1.10000", "%.5f", 1.1);
      test("   1.10000", "%10.5f", 1.1);
      test("   1.11234", "%10.5f", 1.112344);
      test("1112345.00000", "%10.5f", 1112345.0);
#ifdef WINDOWS
      test("1.112345e+006", "%e", 1112345.0);
      test("1.112345E+006", "%E", 1112345.0);
      test("1.112345E+000", "%E", 1.1123450);
#else
      test("1.112345e+06", "%e", 1112345.0);
      test("1.112345E+06", "%E", 1112345.0);
      test("1.112345E+00", "%E", 1.1123450);
#endif /* WINDOWS */
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

  ret = ssh_snprintf((char *)(buf2+10), 10, "kukkuu%s", "RESET");
  if (ret != 9)
    {
      printf("Truncated length not correct: %d\n", ret);
      status++;
    }
  if (strcmp((char *)(buf2+10), "kukkuuRESET") == 0 ||
      strlen((char *)(buf2+10)) != 9 || !testpad(buf2+0) || !testpad(buf2+20))
    {
      printf("buffer overrun detection failed 1\n");
      status++;
    }

  ret = ssh_snprintf((char *)(buf2+10), 10, "kukkuu%07x", 10);
  if (ret != 9)
    {
      printf("Truncated length not correct: %d\n", ret);
      status++;
    }
  if (strcmp((char *)(buf2+10), "kukkuu000000A") == 0 ||
      strlen((char *)(buf2+10)) != 9 || !testpad(buf2+0) || !testpad(buf2+20))
    {
      printf("buffer overrun detection failed 2\n");
      status++;
    }

  ret = ssh_snprintf((char *)(buf2+10), 10, "kukkuu%7x", 10);
  if (ret != 9)
    {
      printf("Truncated length not correct: %d\n", ret);
      status++;
    }
  if (strcmp((char *)(buf2+10), "kukkuu      A") == 0 ||
      strlen((char *)(buf2+10)) != 9 || !testpad(buf2+0) || !testpad(buf2+20))
    {
      printf("buffer overrun detection failed 3\n");
      status++;
    }

  ret = ssh_snprintf((char *)(buf2+10), 10, "kukkuu%f", 3.141592);
  if (ret != 9)
    {
      printf("Truncated length not correct: %d\n", ret);
      status++;
    }
  if (strcmp((char *)(buf2+10), "kukkuu3.141592") == 0 ||
      strlen((char *)(buf2+10)) != 9 || !testpad(buf2+0) || !testpad(buf2+20))
    {
      printf("buffer overrun detection failed 4\n");
      status++;
    }

  ret = ssh_snprintf((char *)(buf2+10), 10, "kukkuu%g", 3.141592);
  if (ret != 9)
    {
      printf("Truncated length not correct: %d\n", ret);
      status++;
    }
  if (strcmp((char *)(buf2+10), "kukkuu3.141592") == 0 ||
      strlen((char *)(buf2+10)) != 9 || !testpad(buf2+0) || !testpad(buf2+20))
    {
      printf("buffer overrun detection failed 5\n");
      status++;
    }

  ret = ssh_snprintf((char *)(buf2+10), 10, "kukkuu%-7f", 3.141592);
  if (ret != 9)
    {
      printf("Truncated length not correct: %d\n", ret);
      status++;
    }
  if (strcmp((char *)(buf2+10), "kukkuu3.141592") == 0 ||
      strlen((char *)(buf2+10)) != 9 || !testpad(buf2+0) || !testpad(buf2+20))
    {
      printf("buffer overrun detection failed 6\n");
      status++;
    }

  ret = ssh_snprintf((char *)(buf2+10), 10, "kukkuu%-+7f", 3.141592);
  if (ret != 9)
    {
      printf("Truncated length not correct: %d\n", ret);
      status++;
    }
  if (strcmp((char *)(buf2+10), "kukkuu+3.141592") == 0 ||
      strlen((char *)(buf2+10)) != 9 || !testpad(buf2+0) || !testpad(buf2+20))
    {
      printf("buffer overrun detection failed 7\n");
      status++;
    }

  ret = ssh_snprintf((char *)(buf2+10), 10, "kuk%-+7f", -3.141592);
  if (ret != 9)
    {
      printf("Truncated length not correct: %d\n", ret);
      status++;
    }
  if (strcmp((char *)(buf2+10), "kuk-3.141592") == 0 ||
      strlen((char *)(buf2+10)) != 9 || !testpad(buf2+0) || !testpad(buf2+20))
    {
      printf("buffer overrun detection failed 8\n");
      status++;
    }

  memset(buf, '-', 5); ret = ssh_snprintf(buf, 5, "%d", 1);
  if (strcmp(buf, "1") != 0 || ret != 1)
    { printf("Number test failed 1\n"); status++; }

  memset(buf, '-', 5); ret = ssh_snprintf(buf, 5, "%d", 10);
  if (strcmp(buf, "10") != 0 || ret != 2)
    { printf("Number test failed 2\n"); status++; }

  memset(buf, '-', 5); ret = ssh_snprintf(buf, 5, "%d", 100);
  if (strcmp(buf, "100") != 0 || ret != 3)
    { printf("Number test failed 3\n"); status++; }

  memset(buf, '-', 5); ret = ssh_snprintf(buf, 5, "%d", 1000);
  if (strcmp(buf, "1000") != 0 || ret != 4)
    { printf("Number test failed 4\n"); status++; }

  memset(buf, '-', 5); ret = ssh_snprintf(buf, 4, "%d", 1000);
  if (strcmp(buf, "100") != 0 || ret != 3)
    { printf("Number test failed 5\n"); status++; }

  memset(buf, '-', 5); ret = ssh_snprintf(buf, 3, "%d", 1000);
  if (strcmp(buf, "10") != 0 || ret != 2)
    { printf("Number test failed 6\n"); status++; }

  memset(buf, '-', 5); ret = ssh_snprintf(buf, 2, "%d", 1000);
  if (strcmp(buf, "1") != 0 || ret != 1)
    { printf("Number test failed 7\n"); status++; }

  memset(buf, '-', 5); ret = ssh_snprintf(buf, 1, "%d", 1000);
  if (strcmp(buf, "") != 0 || ret != 0)
    { printf("Number test failed 8 : ret = %d\n", ret); status++; }

  memset(buf, '-', 5); ret = ssh_snprintf(buf, 5, "%04d", 1);
  if (strcmp(buf, "0001") != 0 || ret != 4)
    { printf("Number test failed 9\n"); status++; }

  memset(buf, '-', 5); ret = ssh_snprintf(buf, 4, "%04d", 1);
  if (strcmp(buf, "000") != 0 || ret != 3)
    { printf("Number test failed 10\n"); status++; }

  memset(buf, '-', 5); ret = ssh_snprintf(buf, 3, "%04d", 1);
  if (strcmp(buf, "00") != 0 || ret != 2)
    { printf("Number test failed 11\n"); status++; }

  memset(buf, '-', 5); ret = ssh_snprintf(buf, 2, "%04d", 1);
  if (strcmp(buf, "0") != 0 || ret != 1)
    { printf("Number test failed 12\n"); status++; }

  memset(buf, '-', 5); ret = ssh_snprintf(buf, 1, "%04d", 1);
  if (strcmp(buf, "") != 0 || ret != 0)
    { printf("Number test failed 13\n"); status++; }

  memset(buf, '-', 10); ret = ssh_snprintf(buf, 5, "%02d:%02d:%02d", 23, 1, 1);
  if (strcmp(buf, "23:0") != 0 || ret != 4)
    {
      printf("Number test failed 14, should return 23:0, returns %s\n", buf);
      status++;
    }

  memset(buf, '-', 10); ret = ssh_snprintf(buf, 10, "%3.0f", 9.999999);
  if (strcmp(buf, " 10") != 0 || ret != 3)
    {
      printf("Number test failed 15, should return / 10/, returns /%s/\n",
             buf);
      status++;
    }

  memset(buf, '-', 10); ret = ssh_snprintf(buf, 4, "%3.0f", 9.999999);
  if (strcmp(buf, " 10") != 0 || ret != 3)
    {
      printf("Number test failed 16, should return / 10/, returns /%s/\n",
             buf);
      status++;
    }

  ssh_util_uninit();
  return status;
}
