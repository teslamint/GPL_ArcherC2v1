/*

  t-dsprintf.c

  Author:
        Sami Lehtinen <sjl@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All rights reserved.
*/

#include "sshincludes.h"
#include "sshdsprintf.h"
#include "sshgetopt.h"

#define SSH_DEBUG_MODULE "TestSshDSprintf"

void test_debug(const char *msg, void *context)
{
  Boolean verbose = *(Boolean *)context;

  if (verbose)
    fprintf(stderr, "t-dsprintf: %s\n", msg);
}

int main(int argc, char **argv)
{
  char *buffer;
  char *buffer2, *should_be;
  int return_value;
  Boolean verbose = FALSE;
  char *s, s2[1000];
#define TEST_LONG_STR "|123456789|123456789|123456789|123456789|"

  ssh_dsprintf((void *)&s, "SSH_ASN1_FUNCTIONS_FOR_TYPE(%s, %s);\n\n", 
               "SshAsn1", TEST_LONG_STR);

  ssh_snprintf(s2, sizeof(s2),
               "SSH_ASN1_FUNCTIONS_FOR_TYPE(%s, %s);\n\n",
               "SshAsn1", TEST_LONG_STR);

  if (strcmp(s, s2) != 0)
    ssh_fatal("ssh_dsprintf does not work on long strings");

  ssh_xfree(s);

  while (1)
    {
      int option;
      ssh_opterr = 0;
      ssh_optallowplus = 1;

      option = ssh_getopt(argc, argv, "d:v", NULL);

      if (option == -1)
        break;

      switch (option)
        {
        case 'd':
          ssh_debug_set_global_level(atoi(ssh_optarg));
          verbose = TRUE;
          break;
        case 'v':
          verbose = TRUE;
          break;
        }
    }

  ssh_debug_register_callbacks(NULL_FNPTR, test_debug, test_debug, &verbose);

  fprintf(stderr, "Running test for ssh_dsprintf, use -v for verbose "
                  "output, and -d <level> to set debug level.\n");

  return_value = ssh_dsprintf((void *)&buffer, "foobar");
  if (strlen(buffer) != return_value)
    {
      printf("Buffer length differ's from characters written. "
             "(buffer len: %lu, return_value: %d\n",
             strlen(buffer), return_value);
      exit(1);
    }
  ssh_xfree(buffer);

  return_value =
    ssh_dsprintf((void *)&buffer,
                 "This is a very long %s to test %s\'s capabilities;\n"
                 "this test was very easy to implement;\n"
                 "%s is much more demanding. You can see that\n"
                 "I\'m a bit bored at the moment, so let\'s add some\n"
                 "exitement:\n"
                 "Here\'s the original string: \n%s\n%s\n%s\n"
                 "It\'s length was %s.\n", "string", "ssh_dsprintf",
                 "ssh2", "<quote>\n", "%s\n", "</quote>",
                 "%d");

  SSH_DEBUG(0, ("first string's length is %d. (ssh_dsprintf wrote " \
                "%d characters.)",\
                strlen(buffer), return_value));

  if (strlen(buffer) != return_value)
    {
      printf("buffer length differ's from characters written. "
             "(buffer len:%lu, return value: %d\n",
             strlen(buffer), return_value);
      exit(1);
    }

  return_value = ssh_dsprintf((void *)&buffer2, buffer, 
                              buffer, strlen(buffer));

  SSH_DEBUG(0, ("second string's length is %d. (ssh_dsprintf wrote " \
                "%d characters.)",\
                strlen(buffer2), return_value));

  if (strlen(buffer2) != return_value)
    {
      printf("buffer2 length differ's from characters written. " \
             "(buffer2 len:%lu, return value: %d\n",
             strlen(buffer2), return_value);
      exit(1);
    }

  if (verbose)
    fprintf(stderr, "%s", buffer2);

  ssh_xfree(buffer);
  ssh_xfree(buffer2);

  should_be =   "pitka/pitka/pitka/pitka/pitka/pitka/pitka/pitka/"
                "pitka/pitka/pitka/pitka/pitka/pitka/pitka/pitka/"
                "pitka";

  return_value =
    ssh_dsprintf((void *)&buffer2, "%s%s%s",
                 "pitka/pitka/pitka/pitka/pitka/pitka/pitka/pitka/"
                 "pitka/pitka/pitka/pitka/pitka/pitka/pitka/pitka",
                 "/", "pitka");

  if (strlen(buffer2) != return_value)
    {
      printf("buffer2 length differ's from characters written. " \
             "(buffer2 len:%lu, return value: %d\n",
             strlen(buffer2), return_value);
      exit(1);
    }

  if (strcmp(buffer2, should_be) != 0)
    {
      printf("should_be: '%s', buffer: '%s'\n", should_be, buffer2);
      exit(1);
    }

  if (verbose)
    fprintf(stderr, "%s\n", buffer2);

  ssh_xfree(buffer2);
  ssh_util_uninit();
  return(0);
}
