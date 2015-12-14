/*
  File: sshicmp-util.h

  Description:
        Convinience functions for handling ICMP

  Copyright:
        Copyright (c) 2005 SFNT Finland Oy.
        All rights reserved
*/

#ifndef SSHICMP_UTIL_H
#define SSHICMP_UTIL_H


/* Convinience function for converting the 'icmp:type(1,0-255)' type
   field of an ICMP or IPV6ICMP traffic selector string in to the
   port encoded format */
char *
ssh_icmputil_string_to_tsstring(const char *string);

#endif /* SSHICMP_UTIL_H */
