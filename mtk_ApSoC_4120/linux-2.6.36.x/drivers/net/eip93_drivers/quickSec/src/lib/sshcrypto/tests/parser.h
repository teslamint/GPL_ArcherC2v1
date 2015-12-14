/*

  parser.c

  Authors: Santeri Paavolainen <santtu@ssh.com>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All rights reserved.

  Simple FILE* based parser functions for parsing strings, data & MPs
  from streams. Does not handle any semantics apart from ignoring
  whitespaces between "tokens" and ignoring comments starting with
  the '#' character.

*/

#ifndef PARSER_H
#define PARSER_H

#include "sshmp.h"

Boolean
file_parser_get_string(FILE *fp, int *line_ptr, char **buf_ret,
                       Boolean string_accepted, Boolean *was_string);

Boolean
file_parser_get_int(FILE *fp, int *line_ptr, int *int_ptr);

Boolean
file_parser_get_data(FILE *fp, int *line_ptr,
                     unsigned char **buf_ret, size_t *len_ret);

Boolean
file_parser_get_mp(FILE *fp, int *line_ptr, SshMPInteger mp);

#endif /* PARSER_H */
