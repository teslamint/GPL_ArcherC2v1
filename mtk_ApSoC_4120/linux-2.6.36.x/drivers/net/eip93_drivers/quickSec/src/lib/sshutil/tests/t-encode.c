/*

t-encode.c

Author: Tatu Ylonen <ylo@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
                   All rights reserved

Tests for the ssh_encode/decode functions.
  - tests encoding / decoding all data types (test_encode)
  - tests encoding empty buffer for all data types (test_empty_decode)
  - tests decoding random garbage for all data types (test_random_decode)
  - tests all functions for at least some arguments (test_functions)

*/

#include "sshincludes.h"
#include "sshencode.h"

#define SSH_DEBUG_MODULE "t-encode"

SshBuffer buffer;

/* This encodes data into a buffer using the given format, and
   compares the result against the expected value.  This also checks
   that data at the beginning of the buffer is not altered. */

void encode_case(const char *name, const char *expect,
                 size_t expect_len, ...)
{
  size_t len, i, bytes;
  unsigned char ch, *cp;
  va_list va;

  ssh_buffer_clear(buffer);
  len = rand() % 100;
  ch = rand();
  for (i = 0; i < len; i++)
    ssh_buffer_append(buffer, &ch, 1);

  va_start(va, expect_len);
  bytes = ssh_encode_buffer_va(buffer, va);

  if (bytes != expect_len || ssh_buffer_len(buffer) != len + expect_len)
    ssh_fatal("test_encode: %s: unexpected length %d vs. %d",
              name, bytes, len + expect_len);
  cp = ssh_buffer_ptr(buffer);
  if (memcmp(expect, cp + len, expect_len) != 0)
    ssh_fatal("test_encode: %s: mismatch", name);

  for (i = 0; i < len; i++)
    if (cp[i] != ch)
      ssh_fatal("test_encode: %s: beginning corrupted", name);
  ssh_buffer_consume(buffer, len);
}

void decode_case_str(SshEncodingFormat fmt, const char *value, size_t valuelen)
{
  unsigned char *cp;
  size_t len, bytes;

  bytes = ssh_buffer_len(buffer);
  if (bytes != ssh_decode_array(ssh_buffer_ptr(buffer), ssh_buffer_len(buffer),
                                      fmt, NULL, NULL, SSH_FORMAT_END))
    ssh_fatal("decode_case_str: NULL decode bad len");
  if (bytes != ssh_decode_buffer(buffer, fmt, &cp, &len, SSH_FORMAT_END))
    ssh_fatal("decode_case_str: bad returned len");
  if (len != valuelen || memcmp(cp, value, len) != 0)
    ssh_fatal("decode_case_str: bad cmp");
  if (ssh_buffer_len(buffer) > 0)
    ssh_fatal("decode_case_str: data left");
  if (cp[len] != 0)
    ssh_fatal("decode_case_str: not null terminated");
  ssh_xfree(cp);
}

void decode_case_int(SshEncodingFormat fmt, unsigned int value)
{
  SshUInt16 lv16;
  SshUInt32 lv32;
  size_t bytes;

  bytes = ssh_buffer_len(buffer);
  if (bytes != ssh_decode_array(ssh_buffer_ptr(buffer), ssh_buffer_len(buffer),
                                      fmt, NULL, SSH_FORMAT_END))
    ssh_fatal("decode_case_int: NULL decode bad len");
  if (fmt == SSH_FORMAT_UINT32)
    {
      if (bytes != ssh_decode_buffer(buffer, fmt, &lv32, SSH_FORMAT_END))
	ssh_fatal("decode_case_int: bad returned len");
      if (lv32 != value)
	ssh_fatal("decode_case_int: bad value");
    }
  else if (fmt == SSH_FORMAT_UINT16)
    {
      if (bytes != ssh_decode_buffer(buffer, fmt, &lv16, SSH_FORMAT_END))
	ssh_fatal("decode_case_int: bad returned len");
      if (lv16 != value)
	ssh_fatal("decode_case_int: bad value");
    }
  else
    ssh_fatal("Unknown fmt");
  if (ssh_buffer_len(buffer) > 0)
    ssh_fatal("decode_case_int: data left");
}

void decode_case_bool(SshEncodingFormat fmt, Boolean value)
{
  Boolean boo;
  size_t bytes;

  bytes = ssh_buffer_len(buffer);
  if (bytes != ssh_decode_array(ssh_buffer_ptr(buffer), ssh_buffer_len(buffer),
                                      fmt, NULL, SSH_FORMAT_END))
    ssh_fatal("decode_case_bool: NULL decode bad len");
  if (bytes != ssh_decode_buffer(buffer, fmt, &boo, SSH_FORMAT_END))
    ssh_fatal("decode_case_bool: bad returned len");
  if (boo != value)
    ssh_fatal("decode_case_bool: bad value");
  if (ssh_buffer_len(buffer) > 0)
    ssh_fatal("decode_case_bool: data left");
}

void decode_case_char(SshEncodingFormat fmt, unsigned char value)
{
  unsigned int ch;
  size_t bytes;

  bytes = ssh_buffer_len(buffer);
  if (bytes != ssh_decode_array(ssh_buffer_ptr(buffer), ssh_buffer_len(buffer),
                                      fmt, NULL, SSH_FORMAT_END))
    ssh_fatal("decode_case_char: NULL decode bad len");
  if (bytes != ssh_decode_buffer(buffer, fmt, &ch, SSH_FORMAT_END))
    ssh_fatal("decode_case_char: bad returned len");
  if (ch != value)
    ssh_fatal("decode_case_char: bad value");
  if (ssh_buffer_len(buffer) > 0)
    ssh_fatal("decode_case_char: data left");
}

void decode_case_data(SshEncodingFormat fmt,
                      const char *value, size_t valuelen)
{
  char buf[1024];
  size_t bytes;

  SSH_ASSERT(valuelen < sizeof(buf));
  bytes = ssh_buffer_len(buffer);
  if (bytes != ssh_decode_array(ssh_buffer_ptr(buffer), ssh_buffer_len(buffer),
                                      fmt, NULL, valuelen, SSH_FORMAT_END))
    ssh_fatal("decode_case_data: NULL decode bad len");
  if (bytes != ssh_decode_buffer(buffer, fmt, buf, valuelen,
                                       SSH_FORMAT_END))
    ssh_fatal("decode_case_data: bad returned len");
  if (memcmp(buf, value, valuelen) != 0)
    ssh_fatal("decode_case_data: bad value");
  if (ssh_buffer_len(buffer) > 0)
    ssh_fatal("decode_case_data: data left");
}

void test_encode(void)
{
  encode_case("uint32_str 0", "\0\0\0\0", 4,
              SSH_ENCODE_UINT32_STR(NULL, 0), SSH_FORMAT_END);
  decode_case_str(SSH_FORMAT_UINT32_STR, "", 0);
  encode_case("uint32_str 0", "\0\0\0\0", 4,
              SSH_ENCODE_UINT32_SSTR("ABC", 0), SSH_FORMAT_END);
  decode_case_str(SSH_FORMAT_UINT32_STR, "", 0);
  encode_case("uint32_str 5", "\0\0\0\5ABCDE", 9,
              SSH_ENCODE_UINT32_SSTR("ABCDEFGHIJK", 5), SSH_FORMAT_END);
  decode_case_str(SSH_FORMAT_UINT32_STR, "ABCDE", 5);

  encode_case("uint32 0x12345678", "\22\64\126\170", 4,
              SSH_ENCODE_UINT32(0x12345678), SSH_FORMAT_END);
  decode_case_int(SSH_FORMAT_UINT32, (SshUInt32) 0x12345678);

  encode_case("uint16 0x1234", "\22\64", 2,
              SSH_ENCODE_UINT16(0x1234), SSH_FORMAT_END);
  decode_case_int(SSH_FORMAT_UINT16, (SshUInt16) 0x1234);

  encode_case("boolean FALSE", "\0", 1,
              SSH_ENCODE_BOOLEAN(FALSE), SSH_FORMAT_END);
  decode_case_bool(SSH_FORMAT_BOOLEAN, FALSE);
  encode_case("boolean TRUE", "\1", 1,
              SSH_ENCODE_BOOLEAN(TRUE), SSH_FORMAT_END);
  decode_case_bool(SSH_FORMAT_BOOLEAN, TRUE);
  encode_case("boolean 0xff", "\1", 1,
              SSH_ENCODE_BOOLEAN(0xff), SSH_FORMAT_END);
  decode_case_bool(SSH_FORMAT_BOOLEAN, TRUE);



  encode_case("char 0x12", "\22", 1,
              SSH_ENCODE_CHAR(0x12), SSH_FORMAT_END);
  decode_case_char(SSH_FORMAT_CHAR, (unsigned int) 0x12);
  encode_case("char 0xee", "\356", 1,
              SSH_ENCODE_CHAR(0xee), SSH_FORMAT_END);
  decode_case_char(SSH_FORMAT_CHAR, (unsigned int) 0xee);
  encode_case("data foo\\0bar", "foo\0bar", 7,
              SSH_ENCODE_DATA("foo\0bar", 7), SSH_FORMAT_END);
  decode_case_data(SSH_FORMAT_DATA, "foo\0bar", 7);
  encode_case("nothing", "", 0, SSH_FORMAT_END);
  if (ssh_buffer_len(buffer) != 0)
    ssh_fatal("``nothing'' encoded to non-empty");
}

void test_empty_decode(void)
{
  if (ssh_decode_array((const unsigned char *) "", 0,
                       SSH_DECODE_UINT32_STR(NULL, NULL),
                       SSH_FORMAT_END) != 0)
    ssh_fatal("test_empty_decode failed");
  if (ssh_decode_array((const unsigned char *) "", 0,
                       SSH_DECODE_UINT32(NULL),
                       SSH_FORMAT_END) != 0)
    ssh_fatal("test_empty_decode failed");
  if (ssh_decode_array((const unsigned char *) "", 0,
                       SSH_DECODE_CHAR(NULL),
                       SSH_FORMAT_END) != 0)
    ssh_fatal("test_empty_decode failed");
  if (ssh_decode_array((const unsigned char *) "", 0,
                       SSH_DECODE_BOOLEAN(NULL),
                       SSH_FORMAT_END) != 0)
    ssh_fatal("test_empty_decode failed");
  if (ssh_decode_array((const unsigned char *) "", 0,
                       SSH_DECODE_DATA(NULL, 0),
                       SSH_FORMAT_END) != 0)
    ssh_fatal("test_empty_decode failed");
}

void test_random_decode(void)
{
  unsigned char buf[16];
  size_t i, j;

  for(j = 0; j < 100; j++)
    {
      for (i = 0; i < sizeof(buf); i++)
	buf[i] = rand();

      ssh_decode_array(buf, sizeof(buf), SSH_DECODE_UINT32_STR(NULL, NULL),
		       SSH_FORMAT_END);
      ssh_decode_array(buf, sizeof(buf), SSH_DECODE_UINT32(NULL),
		       SSH_FORMAT_END);
      ssh_decode_array(buf, sizeof(buf), SSH_DECODE_CHAR(NULL),
		       SSH_FORMAT_END);
      ssh_decode_array(buf, sizeof(buf), SSH_DECODE_BOOLEAN(NULL),
		       SSH_FORMAT_END);
      ssh_decode_array(buf, sizeof(buf), SSH_DECODE_DATA(NULL, 0),
		       SSH_FORMAT_END);
    }
}

void test_functions_parse_compound(SshBuffer buffer, ...)
{
  va_list va;

  va_start(va, buffer);
  if (ssh_decode_array_va(ssh_buffer_ptr(buffer), ssh_buffer_len(buffer), va)
      != 4)
    ssh_fatal("test_functions_parse_compound error");
}

void test_functions(int foo, ...)
{
  va_list va;
  unsigned char *cp;

  ssh_buffer_clear(buffer);

  ssh_buffer_clear(buffer);
  va_start(va, foo);
  if (ssh_encode_buffer_va(buffer, va) != 2)
    ssh_fatal("test_functions: ssh_encode_buffer_va error");
  va_end(va);
  if (memcmp(ssh_buffer_ptr(buffer), "\100\103", 2) != 0)
    ssh_fatal("test_functions: ssh_encode_buffer_va data error");

  va_start(va, foo);
  if (ssh_encode_array_alloc_va(NULL, va) != 2)
    ssh_fatal("test_function: ssh_encode_array_alloc_va NULL error");
  va_end(va);

  va_start(va, foo);
  if (ssh_encode_array_alloc_va(&cp, va) != 2)
    ssh_fatal("test_functions: ssh_encode_array_alloc_va error");
  va_end(va);
  if (memcmp(cp, "\100\103", 2) != 0)
    ssh_fatal("test_functions: ssh_encode_array_alloc_va data error");
  ssh_xfree(cp);
}

static void test1(void)
{
  unsigned char *t1, *t2;

  buffer = ssh_buffer_allocate();
  ssh_encode_buffer(buffer,
    SSH_ENCODE_CHAR(0),
    SSH_ENCODE_DATA("sikapantteri", strlen("sikapantteri")),
    SSH_ENCODE_UINT32_SSTR("sikapantteri", strlen("sikapantteri")),
    SSH_ENCODE_UINT32_SSTR("sikapantteri", strlen("sikapantteri")),
    SSH_FORMAT_END);
  if (ssh_decode_buffer(buffer,
			SSH_DECODE_CHAR(NULL),
			SSH_DECODE_DATA(NULL, strlen("sikapantteri")),
			SSH_DECODE_UINT32_STR(&t1, NULL),
			SSH_DECODE_UINT32_STR(&t2, NULL),
			SSH_FORMAT_END) == 0)
    ssh_fatal("ssh_decode_buffer failed");
  ssh_xfree(t2);
  ssh_xfree(t1);
  ssh_buffer_free(buffer);
}

int main()
{
  int pass;

  test1();
  for (pass = 0; pass < 1000; pass++)
    {
      buffer = ssh_buffer_allocate();
      test_encode();
      test_empty_decode();
      test_random_decode();
      ssh_buffer_free(buffer);
    }
  ssh_util_uninit();
  return 0;
}
