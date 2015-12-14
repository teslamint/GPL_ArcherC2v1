/*

t-time.c

Author: Timo J. Rinne <tri@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
                   All rights reserved

Created: Fri Apr 23 07:58:12 1999 tri

*/

#include "sshincludes.h"
#include "sshrand.h"

void check_time(SshTime tv, int year, int month, int day)
{
  struct SshCalendarTimeRec ct[1], mt[1];
  SshTime cv;

  ssh_calendar_time(tv, ct, FALSE);
  if ((ct->year != year) ||
      ((ct->month + 1) != month) ||
      (ct->monthday != day))
    {
      fprintf(stderr, "ssh_calendar_time returns %04d-%02d-%02d\n",
              (int)ct->year, (int)ct->month + 1, (int)ct->monthday);
      fprintf(stderr, "reference value is %04d-%02d-%02d\n",
              year, month, day);
      exit(1);
    }
  *mt = *ct;
  if (!ssh_make_time(mt, &cv, FALSE))
    ssh_fatal("ssh_make_time fails");

  if (cv != tv)
    ssh_fatal("ssh_make_time returns different time than given "
              "to ssh_calendar_time");
  if (ct->year != mt->year ||
      ct->month != mt->month ||
      ct->monthday != mt->monthday ||
      ct->hour != mt->hour ||
      ct->minute != mt->minute ||
      ct->second != mt->second ||
      ct->weekday != mt->weekday ||
      ct->yearday != mt->yearday ||
      ct->dst != mt->dst ||
      ct->utc_offset != mt->utc_offset)
    ssh_fatal("Time values are different in struct");
  return;
}

int main()
{
  int i, j, k, d, y, p;
  char *a, *b, *first, *last, *rfirst, *rlast;
  SshTime t, t2;
  struct SshCalendarTimeRec ct[1], mt[1];

  ssh_debug_set_level_string("*=6");

  ssh_rand_seed(1234);
  for (i = 0; i < 1000; i++)
    {
      ct->year = 1900 + ssh_rand() % 200;
      ct->month = ssh_rand() % 12;
      ct->monthday = 1 + ssh_rand() % 28;
      ct->hour = ssh_rand() % 24;
      ct->minute = ssh_rand() % 60;
      ct->second = ssh_rand() % 60;
      ct->utc_offset = ((ssh_rand() % 96) - 48) * 900;
      ct->dst = (ssh_rand() % 3) - 1;
      if (!ssh_make_time(ct, &t, FALSE))
        ssh_fatal("ssh_make_time failed");
      ssh_calendar_time(t, mt, FALSE);
      if (ct->year != mt->year ||
          ct->month != mt->month ||
          ct->monthday != mt->monthday ||
          ct->hour != mt->hour ||
          ct->minute != mt->minute ||
          ct->second != mt->second ||
          ct->weekday != mt->weekday ||
          ct->yearday != mt->yearday)
        ssh_fatal("Time values are different in struct");
      if (!ssh_make_time(mt, &t2, TRUE))
        ssh_fatal("ssh_make_time failed");
      if (ct->year != mt->year ||
          ct->month != mt->month ||
          ct->monthday != mt->monthday ||
          ct->hour != mt->hour ||
          ct->minute != mt->minute ||
          ct->second != mt->second ||
          ct->weekday != mt->weekday ||
          ct->yearday != mt->yearday)
        ssh_fatal("Time values are different in struct with local time");
      if (mt->dst)
        t2 -= 3600;
      if (t2 - t != mt->utc_offset)
        ssh_fatal("Localtime vs gmtime values does not match!");
    }

  t = ssh_time();
  a = ssh_time_string(t);
  first = ssh_xstrdup(a);
  rfirst = ssh_readable_time_string(t, TRUE);
  printf("First value was \"%s\" (%s).\n", first, rfirst);
  for (i = 0; i < 5; i++)
    {
      for (j = 0; j < 100; j++)
        for (k = 0; k < 1000; k++)
          {
            b = ssh_time_string(ssh_time());
            if (strcmp(a, b) > 0)
              {
                fprintf(stderr,
                        "t-time: ssh_time_string returned value "
                        "\"%s\" after \"%s\", which doesn't sort right.\n",
                        b, a);
                exit(1);
              }
            ssh_xfree(a);
            a = b;
          }
      printf("Intermediate value #%d was \"%s\".\n", i + 1, a);
    }
  ssh_xfree(a);
  t = ssh_time();
  last = ssh_time_string(t);
  rlast = ssh_readable_time_string(t, TRUE);
  printf("First value was \"%s\" (%s).\n", first, rfirst);
  printf("Last value was \"%s\" (%s).\n", last, rlast);
  ssh_xfree(first);
  ssh_xfree(rfirst);
  ssh_xfree(last);
  ssh_xfree(rlast);
  check_time((SshTime)23200,       1970,  1,  1);   /* 01.01.1970 */
  check_time((SshTime)68212800,    1972,  2, 29);   /* 29.02.1972 */
  check_time((SshTime)946641600,   1999, 12, 31);   /* 31.12.1999 */
  check_time((SshTime)946728000,   2000,  1,  1);   /* 01.01.2000 */
  check_time((SshTime)951825600,   2000,  2, 29);   /* 29.02.2000 */
  check_time((SshTime)2147428800,  2038,  1, 18);   /* 18.01.2038 */
#define T_TIME_TEST_COUNT 25000
  {
    t = ((SshTime)43200) - (((SshTime)86400) * ((SshTime)T_TIME_TEST_COUNT));
    ssh_calendar_time(t, ct, FALSE);
    a = ssh_readable_time_string(t, TRUE);
    printf("Testing weekday consistency from: %s\n", a);
    printf("Be aware that days are in the Gregorian system "
           "even before the Gregorian era.\n");
    ssh_xfree(a);
    d = ct->weekday;
    y = ct->year;
    if ((d < 0) || (d > 6))
      {
        fprintf(stderr,
                "ssh_calendar_time returns %04d-%02d-%02d "
                "with wrong weekday %d\n",
                (int)ct->year,
                (int)ct->month + 1,
                (int)ct->monthday,
                (int)ct->weekday);
        exit(1);
      }
    p = d;
    for (i = 0; i < (T_TIME_TEST_COUNT * 2); i++)
      {
        t += 86400;
        ssh_calendar_time(t, ct, FALSE);
        d = (int)ct->weekday;
        if ((d < 0) || (d > 6) || (d != ((p + 1) % 7)))
          {
            fprintf(stderr,
                    "ssh_calendar_time returns %04d-%02d-%02d "
                    "with inconsistent weekday %d\n",
                    (int)ct->year,
                    (int)ct->month + 1,
                    (int)ct->monthday,
                    (int)ct->weekday);
            exit(1);
          }
#if 1
        if ((((ct->year % 100) == 0) &&
             (ct->month == 0) &&
             (ct->monthday == 1)) ||
            (((((ct->year - 20) % 100) == 0) &&
              (ct->month == 5) &&
              (ct->monthday == 24))))
#endif
          {
            a = ssh_readable_time_string(t, TRUE);
            b = ssh_readable_time_string(t, FALSE);
            printf("Intermediate: %s (universal)\n",b);
            printf("              %s (local)\n", a);
            ssh_xfree(a);
            ssh_xfree(b);
          }
        p = d;
        y = ct->year;
      }
  }
  a = ssh_readable_time_string(t, TRUE);
  printf("Weekday consistency tested until: %s\n", a);
  ssh_xfree(a);
  ssh_util_uninit();
  exit(0);
}

/* eof (t-time.c) */
