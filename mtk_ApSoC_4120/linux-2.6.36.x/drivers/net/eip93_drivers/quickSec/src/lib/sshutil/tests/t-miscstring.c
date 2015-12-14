/*
 *
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
 *  Copyright:
 *          Copyright (c) 2002, 2003 SFNT Finland Oy.
 *                    All rights reserved
 */
/*
 *        Program: util
 *
 *        Creation          : 15:40 Dec 30 1999 kivinen
 *        Last Modification : 02:33 May 11 2000 kivinen
 *        Version           : 1.192
 *        
 *
 *        Description       : Test program for misc string functions.
 *
 */

#include "sshincludes.h"
#include "sshmiscstring.h"

int main(int argc, char **argv)
{
  char buffer[20], *p;

  if (ssh_strnlen("foobar", 3) != 3)
    ssh_fatal("Ssh_strnlen test failed");
  if (ssh_strnlen("foobar", 10) != 6)
    ssh_fatal("Ssh_strnlen test failed");
  if (ssh_strnlen("", 10) != 0)
    ssh_fatal("Ssh_strnlen test failed");
  if (ssh_strnlen("", 0) != 0)
    ssh_fatal("Ssh_strnlen test failed");
  if (ssh_strnlen("aaaaaaaaaaaa", 0) != 0)
    ssh_fatal("Ssh_strnlen test failed");
  if (ssh_strnlen("aaaaaaaaaaaa", 1000) != 12)
    ssh_fatal("Ssh_strnlen test failed");

  if (strcmp((p = ssh_string_concat_2("foo", "bar")),
             "foobar") != 0)
    ssh_fatal("ssh_string_concat_2 failed");
  ssh_free(p);
  if (strcmp((p = ssh_string_concat_2(NULL, "bar")),
             "bar") != 0)
    ssh_fatal("ssh_string_concat_2 failed");
  ssh_free(p);
  if (strcmp((p = ssh_string_concat_2("foo", NULL)),
             "foo") != 0)
    ssh_fatal("ssh_string_concat_2 failed");
  ssh_free(p);
  if (strcmp((p = ssh_string_concat_2(NULL, NULL)),
             "") != 0)
    ssh_fatal("ssh_string_concat_2 failed");
  ssh_free(p);

  if (strcmp((p = ssh_string_concat_3("foo", "bar", "zappa")),
             "foobarzappa") != 0)
    ssh_fatal("ssh_string_concat_3 failed");
  ssh_free(p);
  if (strcmp((p = ssh_string_concat_3("foo", "bar", "zappa")),
             "foobarzappa") != 0)
    ssh_fatal("ssh_string_concat_3 failed");
  ssh_free(p);
  if (strcmp((p = ssh_string_concat_3(NULL, "bar", "zappa")),
             "barzappa") != 0)
    ssh_fatal("ssh_string_concat_3 failed");
  ssh_free(p);
  if (strcmp((p = ssh_string_concat_3("foo", NULL, "zappa")),
             "foozappa") != 0)
    ssh_fatal("ssh_string_concat_3 failed");
  ssh_free(p);
  if (strcmp((p = ssh_string_concat_3("foo", "bar", NULL)),
             "foobar") != 0)
    ssh_fatal("ssh_string_concat_3 failed");
  ssh_free(p);
  if (strcmp((p = ssh_string_concat_3(NULL, NULL, "zappa")),
             "zappa") != 0)
    ssh_fatal("ssh_string_concat_3 failed");
  ssh_free(p);
  if (strcmp((p = ssh_string_concat_3(NULL, "zappa", NULL)),
             "zappa") != 0)
    ssh_fatal("ssh_string_concat_3 failed");
  ssh_free(p);
  if (strcmp((p = ssh_string_concat_3("zappa", NULL, NULL)),
             "zappa") != 0)
    ssh_fatal("ssh_string_concat_3 failed");
  ssh_free(p);
  if (strcmp((p = ssh_string_concat_3(NULL, NULL, NULL)),
             "") != 0)
    ssh_fatal("ssh_string_concat_3 failed");
  ssh_free(p);

  if (strcmp((p = ssh_replace_in_string("foobarzappa", "foo", "bar")),
             "barbarzappa")
      != 0)
    ssh_fatal("ssh_replace_in_string failed");
  ssh_free(p);
  if (strcmp((p = ssh_replace_in_string("foobarzappa", "o", "o")),
             "foobarzappa")
      != 0)
    ssh_fatal("ssh_replace_in_string failed");
  ssh_free(p);
  if (strcmp((p = ssh_replace_in_string("foobarzappa", "o", "a")),
             "faabarzappa")
      != 0)
    ssh_fatal("ssh_replace_in_string failed");
  ssh_free(p);
  if (strcmp((p = ssh_replace_in_string("foobarzappa", "a", "faa")),
             "foobfaarzfaappfaa") != 0)
    ssh_fatal("ssh_replace_in_string failed");
  ssh_free(p);
  if (strcmp((p = ssh_replace_in_string("foobarzappa", "bar", "")),
             "foozappa")
      != 0)
    ssh_fatal("ssh_replace_in_string failed");
  ssh_free(p);

  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 0, 1000),
             "0") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 1, 1000),
             "1") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 9, 1000),
             "9") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 10, 1000),
             "10") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 99, 1000),
             "99") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 100, 1000),
             "100") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 999, 1000),
             "999") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 1000, 1000),
             "1.0k") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 1001, 1000),
             "1.0k") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 1009, 1000),
             "1.0k") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 1010, 1000),
             "1.0k") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 1050, 1000),
             "1.1k") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 1099, 1000),
             "1.1k") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 2000, 1000),
             "2.0k") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 9899, 1000),
             "9.9k") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 9949, 1000),
             "9.9k") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 9950, 1000),
             "10k") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 9999, 1000),
             "10k") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 10000, 1000),
             "10k") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 11000, 1000),
             "11k") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 99000, 1000),
             "99k") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 100000, 1000),
             "100k") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 1000000, 1000),
             "1.0M") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 10000000, 1000),
             "10M") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 100000000, 1000),
             "100M") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 1000000000, 1000),
             "1.0G") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
#ifdef SSHUINT64_IS_64BITS
  if (strcmp(ssh_format_number(buffer, sizeof(buffer),
                               SSH_C64(10000000000), 1000), "10G") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer),
                               SSH_C64(100000000000), 1000), "100G") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer),
                               SSH_C64(1000000000000), 1000), "1.0T") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer),
                               SSH_C64(10000000000000), 1000), "10T") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer),
                               SSH_C64(100000000000000), 1000), "100T") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer),
                               SSH_C64(1000000000000000), 1000), "1.0P") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer),
                               SSH_C64(10000000000000000), 1000), "10P") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer),
                               SSH_C64(100000000000000000), 1000),
             "100P") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer),
                               SSH_C64(1000000000000000000), 1000),
             "1.0E") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer),
                               SSH_C64(10000000000000000000),
                               1000), "10E") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
#endif /* SSHUINT64_IS_64BITS */

  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 0, 1024),
             "0") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 1, 1024),
             "1") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 9, 1024),
             "9") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 10, 1024),
             "10") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 99, 1024),
             "99") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 100, 1024),
             "100") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 999, 1024),
             "999") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 1000, 1024),
             "1000") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 1001, 1024),
             "1001") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 1009, 1024),
             "1009") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 1010, 1024),
             "1010") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 1023, 1024),
             "1023") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 1024, 1024),
             "1.0k") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 1050, 1024),
             "1.0k") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 1099, 1024),
             "1.1k") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 2000, 1024),
             "2.0k") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 9899, 1024),
             "9.7k") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 9999, 1024),
             "9.8k") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 10000, 1024),
             "9.8k") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 10187, 1024),
             "9.9k") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 10189, 1024),
             "10k") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 11000, 1024),
             "11k") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 99000, 1024),
             "97k") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 100000, 1024),
             "98k") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 1000000, 1024),
             "977k") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 1048575, 1024),
             "1.0M") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 1048576, 1024),
             "1.0M") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 10000000, 1024),
             "9.5M") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 100000000, 1024),
             "95M") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 1000000000, 1024),
             "954M") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer), 1048576*1024, 1024),
             "1.0G") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
#ifdef SSHUINT64_IS_64BITS
  if (strcmp(ssh_format_number(buffer, sizeof(buffer),
                               SSH_C64(10000000000), 1024), "9.3G") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer),
                               SSH_C64(100000000000), 1024), "93G") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer),
                               SSH_C64(1000000000000), 1024), "931G") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer),
                               SSH_C64(1099511627776), 1024), "1.0T") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer),
                               SSH_C64(10000000000000), 1024), "9.1T") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer),
                               SSH_C64(100000000000000), 1024), "91T") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer),
                               SSH_C64(1000000000000000), 1024), "909T") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer),
                               SSH_C64(1125899906842624), 1024), "1.0P") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer),
                               SSH_C64(10000000000000000), 1024), "8.9P") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer),
                               SSH_C64(100000000000000000), 1024), "89P") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer),
                               SSH_C64(1000000000000000000), 1024),
             "888P") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer),
                               SSH_C64(1152921504606846976), 1024),
             "1.0E") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, sizeof(buffer),
                               SSH_C64(10000000000000000000),
                               1024), "8.7E") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
#endif /* SSHUINT64_IS_64BITS */

  if (strcmp(ssh_format_number(buffer, 5, 1000, 1024),
             "1000") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, 4, 1000, 1024),
             "100") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, 3, 1000, 1024),
             "10") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, 2, 1000, 1024),
             "1") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);
  if (strcmp(ssh_format_number(buffer, 1, 1000, 1024),
             "") != 0)
    ssh_fatal("ssh_format_number failed: %s", buffer);

  if (strcmp(ssh_format_time(buffer, sizeof(buffer), 0),
             "00:00:00") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, sizeof(buffer), 59),
             "00:00:59") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, sizeof(buffer), 60),
             "00:01:00") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, sizeof(buffer), 61),
             "00:01:01") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, sizeof(buffer), 119),
             "00:01:59") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, sizeof(buffer), 120),
             "00:02:00") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, sizeof(buffer), 3599),
             "00:59:59") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, sizeof(buffer), 3600),
             "01:00:00") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, sizeof(buffer), 3601),
             "01:00:01") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, sizeof(buffer), 3661),
             "01:01:01") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, sizeof(buffer), 3661 + 3600),
             "02:01:01") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, sizeof(buffer), 3661 + 2 * 3600),
             "03:01:01") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, sizeof(buffer), 3661 + 22 * 3600),
             "23:01:01") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, sizeof(buffer), 86399),
             "23:59:59") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, sizeof(buffer), 86400),
             "1+00:00") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, sizeof(buffer), 86460),
             "1+00:01") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, sizeof(buffer), 86520),
             "1+00:02") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, sizeof(buffer), 86400 + 3600),
             "1+01:00") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, sizeof(buffer), 86400 + 3600 + 60),
             "1+01:01") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, sizeof(buffer), 86400 + 86399),
             "1+23:59") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, sizeof(buffer), 86400 * 2 + 86399),
             "2+23:59") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, sizeof(buffer), 86400 * 9 + 86399),
             "9+23:59") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, sizeof(buffer), 86400 * 10 + 86399),
             "10+23:59") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, sizeof(buffer), 86400 * 99 + 86399),
             "99+23:59") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, sizeof(buffer), 86400 * 100 + 86399),
             "100+23") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, sizeof(buffer), 86400 * 999 + 86399),
             "999+23") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, sizeof(buffer), 86400 * 1000 + 86399),
             "1000+23") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, sizeof(buffer), 86400 * 10000 + 86399),
             "10000+23") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);

#ifdef SSHUINT64_IS_64BITS
  if (strcmp(ssh_format_time(buffer, sizeof(buffer),
                             SSH_C64(8640000000) + 86399),
             "100000") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, sizeof(buffer),
                             SSH_C64(86400000000) + 86399),
             "1000000") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, sizeof(buffer),
                             SSH_C64(864000000000) + 86399),
             "10000000") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 9,
                             SSH_C64(864000000000) + 86399),
             "10000000") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 8,
                             SSH_C64(864000000000) + 86399),
             "1000000") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 7,
                             SSH_C64(864000000000) + 86399),
             "100000") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 6,
                             SSH_C64(864000000000) + 86399),
             "10000") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 5,
                             SSH_C64(864000000000) + 86399),
             "1000") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 4,
                             SSH_C64(864000000000) + 86399),
             "100") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 3,
                             SSH_C64(864000000000) + 86399),
             "10") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 2,
                             SSH_C64(864000000000) + 86399),
             "1") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 1,
                             SSH_C64(864000000000) + 86399),
             "") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
#endif /* SSHUINT64_IS_64BITS */

  if (strcmp(ssh_format_time(buffer, 9, 86400 * 10000 + 86399),
             "10000+23") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 8, 86400 * 10000 + 86399),
             "10000+2") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 7, 86400 * 10000 + 86399),
             "10000+") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 6, 86400 * 10000 + 86399),
             "10000") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 5, 86400 * 10000 + 86399),
             "1000") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 4, 86400 * 10000 + 86399),
             "100") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 3, 86400 * 10000 + 86399),
             "10") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 2, 86400 * 10000 + 86399),
             "1") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 1, 86400 * 10000 + 86399),
             "") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);

  if (strcmp(ssh_format_time(buffer, 9, 86400 * 99 + 86399),
             "99+23:59") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 8, 86400 * 99 + 86399),
             "99+23:5") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 7, 86400 * 99 + 86399),
             "99+23:") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 6, 86400 * 99 + 86399),
             "99+23") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 5, 86400 * 99 + 86399),
             "99+2") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 4, 86400 * 99 + 86399),
             "99+") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 3, 86400 * 99 + 86399),
             "99") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 2, 86400 * 99 + 86399),
             "9") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 1, 86400 * 99 + 86399),
             "") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);

  if (strcmp(ssh_format_time(buffer, 9, 3661 + 22 * 3600),
             "23:01:01") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 8, 3661 + 22 * 3600),
             "23:01:0") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 7, 3661 + 22 * 3600),
             "23:01:") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 6, 3661 + 22 * 3600),
             "23:01") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 5, 3661 + 22 * 3600),
             "23:0") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 4, 3661 + 22 * 3600),
             "23:") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 3, 3661 + 22 * 3600),
             "23") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 2, 3661 + 22 * 3600),
             "2") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);
  if (strcmp(ssh_format_time(buffer, 1, 3661 + 22 * 3600),
             "") != 0)
    ssh_fatal("ssh_format_time failed: %s", buffer);

  p = ssh_get_component_data_from_string("component(test1)", "component", 0);
  if (p == NULL ||
      strcmp(p, "test1") != 0)
    ssh_fatal("ssh_get_component_data_from_string failed");
  ssh_xfree(p);

  p = ssh_get_component_data_from_string("component()", "component", 0);
  if (p == NULL ||
      strcmp(p, "") != 0)
    ssh_fatal("ssh_get_component_data_from_string failed");
  ssh_xfree(p);

  p = ssh_get_component_data_from_string("componentboo(test1)",
                                         "component", 0);
  if (p != NULL)
    ssh_fatal("ssh_get_component_data_from_string failed");

  p = ssh_get_component_data_from_string("component(data())", "component", 0);
  if (p == NULL ||
      strcmp(p, "data()") != 0)
    ssh_fatal("ssh_get_component_data_from_string failed");
  ssh_xfree(p);

  p = ssh_get_component_data_from_string("component(data(data()))",
                                         "component", 0);
  if (p == NULL ||
      strcmp(p, "data(data())") != 0)
    ssh_fatal("ssh_get_component_data_from_string failed");
  ssh_xfree(p);


  p = ssh_get_component_data_from_string("component(test1)", "component", 1);
  if (p != NULL)
    ssh_fatal("ssh_get_component_data_from_string failed");
  ssh_xfree(p);

  p = ssh_get_component_data_from_string("component()", "component", 1);
  if (p != NULL)
    ssh_fatal("ssh_get_component_data_from_string failed");

  p = ssh_get_component_data_from_string("componentboo(test1)",
                                         "component", 1);
  if (p != NULL)
    ssh_fatal("ssh_get_component_data_from_string failed");

  p = ssh_get_component_data_from_string("component(different_data()) "
                                         "component(data())", "component", 1);
  if (p == NULL ||
      strcmp(p, "data()") != 0)
    ssh_fatal("ssh_get_component_data_from_string failed");
  ssh_xfree(p);

  p = ssh_get_component_data_from_string("component(different_data()) "
                                         "component(data(data()))",
                                         "component", 1);
  if (p == NULL ||
      strcmp(p, "data(data())") != 0)
    ssh_fatal("ssh_get_component_data_from_string failed");
  ssh_xfree(p);


  p = ssh_get_component_data_from_string("component(different_data()) "
                                         "component(different_data()) "
                                         "component(test1)", "component", 2);
  if (p == NULL ||
      strcmp(p, "test1") != 0)
    ssh_fatal("ssh_get_component_data_from_string failed");
  ssh_xfree(p);

  p = ssh_get_component_data_from_string("component(different_data()) "
                                         "component(different_data()) "
                                         "component()", "component", 2);
  if (p == NULL ||
      strcmp(p, "") != 0)
    ssh_fatal("ssh_get_component_data_from_string failed");
  ssh_xfree(p);

  p = ssh_get_component_data_from_string("component(different_data()) "
                                         "component(different_data()) "
                                         "componentboo(test1)",
                                         "component", 2);
  if (p != NULL)
    ssh_fatal("ssh_get_component_data_from_string failed");

  p = ssh_get_component_data_from_string("component(different_data()) "
                                         "component(different_data()) "
                                         "component(data())", "component", 2);
  if (p == NULL ||
      strcmp(p, "data()") != 0)
    ssh_fatal("ssh_get_component_data_from_string failed");
  ssh_xfree(p);

  p = ssh_get_component_data_from_string("component(different_data()) "
                                         "component(different_data()) "
                                         "component(data(data()))",
                                         "component", 2);
  if (p == NULL ||
      strcmp(p, "data(data())") != 0)
    ssh_fatal("ssh_get_component_data_from_string failed");
  ssh_xfree(p);

  ssh_util_uninit();
  exit(0);
}
