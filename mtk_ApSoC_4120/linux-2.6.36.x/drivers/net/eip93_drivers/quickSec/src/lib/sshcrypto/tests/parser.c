/*

  parser.c

  Authors: Santeri Paavolainen <santtu@ssh.com>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All rights reserved.

  This file contains the implementation of a simple file parser
  (tokenizer, more precisely).

*/

#include "sshincludes.h"
#include "parser.h"

#define SSH_DEBUG_MODULE "TestParser"

Boolean
file_parser_get_string(FILE *fp, int *line_ptr, char **buf_ret,
                       Boolean string_accepted, Boolean *was_string)
{
  int i, len, c, size;
  char *buf;
  Boolean string, quote, comment;

  i = len = size = 0;
  buf = NULL;
  quote = string = comment = FALSE;

  while (1)
    {
      if ((len + 1) >= size)
        {
          int new_size;
          new_size = size ? size * 2 : 512;
          if (!(buf = ssh_realloc(buf, size, new_size)))
            {
              ssh_free(buf);
              return FALSE;
            }
          size = new_size;
        }

      if ((c = fgetc(fp)) == EOF)
        {
          if (i == 0 || string)
            {
              ssh_xfree(buf);
              return FALSE;
            }
          break;
        }

      if (comment)
        {
          if (c == '\n')
            {
              (*line_ptr)++;
              comment = FALSE;
            }

          continue;
        }

      if (quote)
        {
          quote = FALSE;

          /* Quoted newlines are silently eaten */
          if (c == '\n')
            {
              (*line_ptr)++;
              continue;
            }

          buf[len++] = c;
          continue;
        }

      if (c == '\\')
        {
          quote = TRUE;
          continue;
        }

      if (string)
        {
          i++;

          if (c == '"')
            break;

          buf[len++] = c;
          continue;
        }

      /* Not string */

      /* Comment start? */
      if (c == '#')
        {
          comment = TRUE;
          continue;
        }

      /* Whitespace is eaten at beginning, but otherwise marks end of
         string */
      if (isspace(c))
        {
          if (i != 0)
            {
              /* Push it back */
              ungetc(c, fp);
              break;
            }

          if (c == '\n')
            (*line_ptr)++;

          continue;
        }

      /* Beginning of string? Only if accepted. */
      if (i == 0 && c == '\"' && !string && string_accepted)
        {
          string = TRUE;
          continue;
        }

      buf[len++] = c;
      i++;
    }

  if (was_string)
    *was_string = string;

  buf[len++] = '\0';

  *buf_ret = buf;

  return TRUE;
}

Boolean
file_parser_get_int(FILE *fp, int *line_ptr, int *int_ptr)
{
  char *x;

  if (!file_parser_get_string(fp, line_ptr, &x, FALSE, NULL))
    return FALSE;

  *int_ptr = strtol(x, NULL, 0);

  ssh_free(x);

  return TRUE;
}

Boolean
file_parser_get_data(FILE *fp, int *line_ptr,
                     unsigned char **buf_ret, size_t *len_ret)
{
  char *data;
  int len, i;
  Boolean string;

  if (!file_parser_get_string(fp, line_ptr, (char **) &data, TRUE, &string))
    return FALSE;

  len = strlen(data);

  if (string)
    {
      *buf_ret = (unsigned char *) data;
      *len_ret = len;
      return TRUE;
    }

  if (len % 2)
    {
      SSH_DEBUG(0, ("Hexadecimal input data has an odd length."));
      ssh_free(data);
      return FALSE;
    }

#define HEX(CH)                                                          \
      (((CH) >= '0' && (CH) <= '9') ? ((CH) - '0' ) : \
         (tolower((unsigned char) (CH)) - 'a' + 10))

  for (i = 0; i < len; i += 2)
    {
      ((unsigned char *) data)[i / 2] =
        (HEX(data[i]) << 4) | HEX(data[i + 1]);
    }

  *buf_ret = (unsigned char *) data;
  *len_ret = len / 2;

  return TRUE;
}

Boolean
file_parser_get_mp(FILE *fp, int *line_ptr, SshMPInteger mp)
{
  unsigned char *buf;
  size_t len, got;

  if (!file_parser_get_data(fp, line_ptr, &buf, &len))
    return FALSE;

  got = ssh_mprz_decode_rendered(buf, len, mp);

  ssh_free(buf);

  if (len != got)
    {
      SSH_DEBUG(0, ("Could not decode encoded MP-Integer: "
                    "gave %d, used %d bytes", len, got));
      return FALSE;
    }

  return TRUE;
}
