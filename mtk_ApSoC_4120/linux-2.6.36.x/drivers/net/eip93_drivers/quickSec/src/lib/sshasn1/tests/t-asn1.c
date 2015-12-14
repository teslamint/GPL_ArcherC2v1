/*

  t-asn1.c

  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All rights reserved.

  Created: Mon Feb 24 16:48:04 1997 [mkojo]

  ASN.1 tester. Runs some tests that should be good enough for
  testing the ASN.1 code (i.e. parser if you like to call it that).

  What should be noted is that the ASN.1 code is not generic ASN.1 but
  a simplified subset. It features integrated BER/DER encoding.

  NOTES:

    - One significant problem (it seems) is that when traversing the
      ASN.1 tree one cannot go up! Thus we need some additional stuff for
      that which isn't nice. Going up should be implemented.

  */

#include "sshincludes.h"
#include "sshmp.h"
#include "sshasn1.h"
#include "sshtimemeasure.h"

void print_tree(SshAsn1Tree tree)
{
  ssh_asn1_print_tree(tree);
}

void test(void)
{
  SshAsn1Context context;
  SshAsn1Tree tree;
  SshAsn1Status status;
  const unsigned char *string = (const unsigned char *) "my string";

  context = ssh_asn1_init();
  status = ssh_asn1_create_tree(context, &tree,
                                "(sequence ()"
                                "  (sequence ()"
                                "     (octet-string (1)))"
                                "  (bit-string (2)))",
                                string, strlen((char *)string),
                                string, strlen((char *)string)
                                );

  printf("status %d\n", status);

  print_tree(tree);

  status = ssh_asn1_encode(context, tree);
  printf("status %d\n", status);

  print_tree(tree);

  ssh_asn1_free(context);

}

unsigned int verbose;

const char *test_string_1 = "This is just a plain test string.";
const char *test_string_2 = "This is just another plain test string.";
const char *test_string_3 = "holabaloo.";
const char *test_string_4 = "When times are tough...";
const char *test_string_5 = "1";
const char *test_string_6 = "2";
const char *test_string_7 = "3";
const char *test_string_8 = "4";
const char *test_string_9 = "5";
const char *test_string_10 = "6";
const char *test_string_11 = "7";
const char *test_string_12 = "8";

void test_1(void)
{
  SshAsn1Context context;
  SshAsn1Tree tree;
  SshAsn1Status status;
  unsigned char *data;
  size_t length;
  SshMPIntegerStruct integer;
  char *oid = "1.2.840.113549.1";
  unsigned char bit_string[3] = { 0x6e, 0x5d, 0xc0 };
  Boolean boolean_value = TRUE;

  ssh_mprz_init_set_si(&integer, -129);

  /* Allocate context for asn1 work. */
  context = ssh_asn1_init();

  status = ssh_asn1_create_tree(context, &tree,
                                "(sequence ()"
                                "  (boolean ())"
                                "  (bit-string ())"
                                "  (sequence ()"
                                "    (octet-string ()) "
                                "    (set ()"
                                "      (object-identifier ())"
                                "      (octet-string ())"
                                "      (set () "
                                "        (octet-string ())"
                                "        (octet-string ())"
                                "        (octet-string ())"
                                "        (octet-string ()))"
                                "      (octet-string ())"
                                "      (sequence ()"
                                "         (octet-string())))"
                                "    (octet-string ())"
                                "    (integer ())))",
                                boolean_value,
                                bit_string, (size_t) 18,
                                test_string_1, strlen(test_string_1),
                                oid,
                                test_string_2, strlen(test_string_2),
                                test_string_3, strlen(test_string_3),
                                test_string_4, strlen(test_string_4),
                                test_string_7, strlen(test_string_7),
                                test_string_8, strlen(test_string_8),
                                test_string_9, strlen(test_string_9),
                                test_string_10, strlen(test_string_10),
                                test_string_11, strlen(test_string_11),
                                &integer
                            );
  ssh_mprz_clear(&integer);


  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error (1): status %d\n", status);
      exit(1);
    }

  /* Print the just created tree. */
  if (verbose)
    print_tree(tree);

  /* Do the encoding. */
  status = ssh_asn1_encode(context, tree);

  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error (2): status %d\n", status);
      exit(1);
    }

  /* Get the encoded BER data. */
  ssh_asn1_get_data(tree, &data, &length);

  /* Free the context and everything in it. */
  ssh_asn1_free(context);

  /* Test reading it. */
  context = ssh_asn1_init();

  status = ssh_asn1_decode(context, data, length, &tree);

  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error: (3) status %d.\n", status);
      exit(1);
    }

  /* Print decoded tree. */
  if (verbose)
    print_tree(tree);

  ssh_asn1_free(context);
  ssh_xfree(data);
}

void test_2(void)
{
  SshAsn1Context context;
  SshAsn1Status status;
  SshAsn1Tree tree;
  SshAsn1Node node;
  char *oid = "1.2.3234234.23423.34.3.23";
  SshMPIntegerStruct int_1, int_2, int_3;
  unsigned char *data;
  size_t length;

  ssh_mprz_init_set_ui(&int_1, 1);
  ssh_mprz_init_set_ui(&int_2, 93842359);
  ssh_mprz_init_set_ui(&int_3, 439223);

  /* Initialize the asn1 allocation context. */
  context = ssh_asn1_init();

  status = ssh_asn1_create_tree(context, &tree,
                                "(sequence (pe 1001)"
                                " (object-identifier (p 1238734))"
                                " (sequence (a 43)"
                                "  (integer (a 1))"
                                "  (integer (a 55))"
                                "  (integer (a 129343556))))",
                                oid,
                                &int_1, &int_2, &int_3);

  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error (2,1): status %d.\n", status);
      exit(1);
    }

  status = ssh_asn1_create_node(context, &node,
                                "(object-identifier ()) "
                                "(sequence ()"
                                " (integer ())"
                                " (integer ())"
                                " (integer ()))",
                                oid,
                                &int_1, &int_2, &int_3);

  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error (2,2): status %d.\n", status);
      exit(1);
    }


  ssh_asn1_reset_tree(tree);
  /* Find last in first row. */
  while (ssh_asn1_move_forward(tree, 1))
    ;

  status = ssh_asn1_insert_list(ssh_asn1_get_current(tree), NULL, node);
  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error (2,3): status %d.\n", status);
      exit(1);
    }

  ssh_asn1_reset_tree(tree);
  if (verbose)
    print_tree(tree);


  status = ssh_asn1_encode(context, tree);
  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error (2,4): status %d.\n", status);
      exit(1);
    }

  ssh_asn1_get_data(tree, &data, &length);
  ssh_asn1_free(context);

  ssh_xfree(data);
  ssh_mprz_clear(&int_1);
  ssh_mprz_clear(&int_2);
  ssh_mprz_clear(&int_3);
}

void test_3(void)
{
  SshAsn1Context context;
  SshAsn1Tree tree;
  SshAsn1Status status;
  unsigned char data[] =
  {
    0x60, 0x81, 0x85,
    0x61, 0x10,
    0x1a, 0x04, 'J', 'o', 'h', 'n',
    0x1a, 0x01, 'P',
    0x1a, 0x05, 'S', 'm', 'i', 't', 'h',
    0xa0, 0x0a,
    0x1a, 0x08, 'D', 'i', 'r', 'e', 'c', 't', 'o', 'r',
    0x42, 0x01, 0x33,
    0xa1, 0x0a,
    0x43, 0x08, '1', '9', '7', '1', '0', '9', '1', '7',
    0xa2, 0x12,
    0x61, 0x10,
    0x1a, 0x04, 'M', 'a', 'r', 'y',
    0x1a, 0x01, 'T',
    0x1a, 0x05, 'S', 'm', 'i', 't', 'h',
    0xa3, 0x42,
    0x31, 0x1f,
    0x61, 0x11,
    0x1a, 0x05, 'R', 'a', 'l', 'p', 'h',
    0x1a, 0x01, 'T',
    0x1a, 0x05, 'S', 'm', 'i', 't', 'h',
    0xa0, 0x0a,
    0x43, 0x08, '1', '9', '5', '7', '1', '1', '1', '1',
    0x31, 0x1f,
    0x61, 0x11,
    0x1a, 0x05, 'S', 'u', 's', 'a', 'n',
    0x1a, 0x01, 'B',
    0x1a, 0x05, 'J', 'o', 'n', 'e', 's',
    0xa0, 0x0a,
    0x43, 0x08, '1', '9', '5', '9', '0', '7', '1', '7',
  };

  /* Initialize the asn.1 context. */
  context = ssh_asn1_init();

  if (verbose)
    printf("Full length: %08x %d\n", sizeof(data) - 3, sizeof(data) - 3);

  status = ssh_asn1_decode(context, data, sizeof(data), &tree);

  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error (3, 1): status report %d.\n", status);
      exit(1);
    }

  if (verbose)
    print_tree(tree);

  ssh_asn1_free(context);
}

void test_4(void)
{
  SshAsn1Context context;
  SshAsn1Tree tree;
  SshAsn1Status status;
  Boolean boolean_value;
  unsigned char *new_str;
  size_t new_str_len;
  const unsigned char *string = (const unsigned char *)
    "Secret string not to be found.";
  const unsigned char *string_2 = (const unsigned char *)
    "Most things in life aren't free...";

  context = ssh_asn1_init();

  boolean_value = FALSE;

  status = ssh_asn1_create_tree(context, &tree,
                                "(sequence (a 50)"
                                "  (boolean (c 1))"
                                "  (octet-string (c 2))"
                                "  (sequence ()"
                                "    (sequence ()"
                                "       (sequence (a 10)"
                                "          (octet-string (c 987))))))",
                                boolean_value,
                                string, strlen((char *) string) + 1,
                                string_2, strlen((char *) string_2) + 1);

  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error: (4,1)\n");
      exit(1);
    }
  if (verbose)
    print_tree(tree);


  status = ssh_asn1_read_tree(context, tree,
                              "(sequence (a 50)"
                              "  (sequence ()"
                              "    (sequence ()"
                              "      (sequence (a 10)"
                              "        (octet-string (c 987))))))",
                              &new_str, &new_str_len);

  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error: (4, 2)\n");
      exit(1);
    }

  if (verbose)
    printf("new_str: %s\n", new_str);

  ssh_xfree(new_str);

#if 0
  status = ssh_asn1_search_tree(tree, "(octet-string (c 987))");

  if (status == SSH_ASN1_STATUS_OK)
    {
      status = ssh_asn1_read_node(context,
                                  ssh_asn1_get_current(tree),
                                  "(octet-string (c 987))",
                              &new_str, &new_str_len);

      if (status != SSH_ASN1_STATUS_OK)
        {
          printf("error: (4, 3)\n");
          exit(1);
        }

      if (verbose)
        printf("new_str: %s", new_str);
      ssh_xfree(new_str);
    }
  else
    {
      if (status == SSH_ASN1_STATUS_MATCH_NOT_FOUND)
        {
          printf("error: (4, 4) Could not locate.\n");
        }
      else
        {
          printf("error: (4, 5) %d.\n", status);
        }
      exit(1);
    }
#endif
  ssh_asn1_free(context);
}

void test_5(void)
{
  SshAsn1Status status;
  SshAsn1Context context;
  SshAsn1Tree tree;
  SshMPIntegerStruct int_1, int_2, int_3, int_4, int_5, int_6, int_7, temp;
  char *oid = "1.2.840.113549.1";
  unsigned char bit_string[3] = { 0x6e, 0x5d, 0xc0 };

  ssh_mprz_init_set_ui(&int_1, 0);
  ssh_mprz_init_set_ui(&int_2, 343);
  ssh_mprz_init_set_si(&int_3, -4982735);
  ssh_mprz_init_set_ui(&int_4, 545);
  ssh_mprz_init_set_ui(&int_5, 541);
  ssh_mprz_init_set_ui(&int_6, 55);
  ssh_mprz_init_set_ui(&int_7, 9873245);
  ssh_mprz_init_set_ui(&temp, 0);

  context = ssh_asn1_init();

  status =
    ssh_asn1_create_tree
    (context,
     &tree,
     "(sequence (a 1)"
     "  (sequence (a 2)"
     "    (integer (1))"
     "    (integer (2))"
     "    (sequence (a 3)"
     "      (integer (3))"
     "      (sequence (a 4)"
     "        (integer (4)))"
     "      (sequence (a 4)"
     "        (integer (5))))"
     "    (integer (6))"
     "    (integer (7))"
     "    (object-identifier (20))"
     "    (bit-string (22))))",
     &int_1, &int_2, &int_3, &int_4, &int_5, &int_6, &int_7,
     oid, bit_string, (size_t)18);

  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error: (5,1) %d.\n", status);
      exit(1);
    }

  if (verbose)
    print_tree(tree);


  ssh_mprz_clear(&temp);

  ssh_mprz_clear(&int_1);
  ssh_mprz_clear(&int_2);
  ssh_mprz_clear(&int_3);
  ssh_mprz_clear(&int_4);
  ssh_mprz_clear(&int_5);
  ssh_mprz_clear(&int_6);
  ssh_mprz_clear(&int_7);
  ssh_asn1_free(context);
}

void test_6(void)
{
  SshAsn1Status status;
  SshAsn1Context context;
  SshAsn1Tree tree;
  SshMPIntegerStruct int_1, int_2, int_3, int_4, int_5, int_6, int_7, temp;

  ssh_mprz_init_set_ui(&int_1, 9843841);
  ssh_mprz_init_set_ui(&int_2, 343);
  ssh_mprz_init_set_si(&int_3, -4982735);
  ssh_mprz_init_set_ui(&int_4, 545);
  ssh_mprz_init_set_ui(&int_5, 43541);
  ssh_mprz_init_set_ui(&int_6, 55);
  ssh_mprz_init_set_ui(&int_7, 9873245);
  ssh_mprz_init_set_ui(&temp, 0);

  context = ssh_asn1_init();

  status =
    ssh_asn1_create_tree
    (context,
     &tree,
     "(sequence (a 1) "
       "(set (a 2) "
         "(integer (1))"
         "(integer (1))"
         "(integer (1))"
         "(integer (1))"
         "(integer (1))"
         "(integer (1))"
         "(integer (1))))",
     &int_1, &int_2, &int_3, &int_4, &int_5, &int_6, &int_7);

  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error: (6,1) %d.\n", status);
      exit(1);
    }

  if (verbose)
    print_tree(tree);

  /* Sort to correct order! */

  ssh_mprz_clear(&temp);

  ssh_mprz_clear(&int_1);
  ssh_mprz_clear(&int_2);
  ssh_mprz_clear(&int_3);
  ssh_mprz_clear(&int_4);
  ssh_mprz_clear(&int_5);
  ssh_mprz_clear(&int_6);
  ssh_mprz_clear(&int_7);
  ssh_asn1_free(context);
}

void test_7(void)
{
  SshAsn1Status status;
  SshAsn1Context context;
  SshAsn1Tree tree, tmp_tree;
  SshAsn1Node any;
  unsigned char *str_1, *str_2, *str_3;
  size_t str_1_len, str_2_len, str_3_len;
  unsigned int which1, which2;
  Boolean boolean_value, found;

  boolean_value = TRUE;

  context = ssh_asn1_init();

  status =
    ssh_asn1_create_tree
    (context, &tree,
     /* This is something which might look like what is rather complicated
        to parse in real life. */
     "(sequence ()"
     "  (sequence (1)"
     "     (octet-string (0)))"
     "  (sequence ()"
     "     (boolean ())"
     "     (octet-string ()))"
     "  (octet-string (4)))",
     test_string_1, strlen(test_string_1),
     boolean_value,
     test_string_2, strlen(test_string_2),
     test_string_3, strlen(test_string_3));

  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error: (7, 1) %d.\n", status);
      exit(1);
    }

  if (verbose)
    print_tree(tree);

  /* Now we show that reading from thus complicated object isn't really
     complicated. */
  status =
    ssh_asn1_read_tree
    (context, tree,
     "(sequence ()"
     /* Very simple objects can be selected by choice. */
     "  (choice"
     "    (sequence (0) (octet-string (1)))"
     "    (sequence (1) (octet-string (0))))"
     /* For little bit more complex we suggest the any construct. */
     "  (any ())"
     "  (optional (octet-string (10)))"
     "  (choice"
     "    (octet-string (100))"
     "    (octet-string (4))))",
     &which1, &str_1, &str_1_len, &str_1, &str_1_len,
     &any,
     &found, &str_3, &str_3_len,
     &which2, &str_2, &str_2_len, &str_2, &str_2_len);

  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error: (7, 2) %d.\n", status);
      exit(1);
    }

  tmp_tree = ssh_asn1_init_tree(context, any, any);

  if (verbose)
    {
      printf("Printing the any field.\n");
      print_tree(tmp_tree);
    }

  printf("Matches at: %d %d\n", which1, which2);

  ssh_xfree(str_1);
  ssh_xfree(str_2);

  status = ssh_asn1_read_node(context, any,
                              "(sequence ()"
                              "(boolean ())"
                              "(octet-string ()))",
                              &boolean_value,
                              &str_1, &str_1_len);

  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error: (7, 3) %d.\n", status);
      exit(1);
    }

  printf("bool %d\n", boolean_value);
  ssh_xfree(str_1);
  ssh_asn1_free(context);
}

void test_8(void)
{
  SshAsn1Status status;
  SshAsn1Context context;
  SshAsn1Tree tree;
  SshMPIntegerStruct int_1, int_2, int_3;
  SshTimeMeasure tm;
  int i;

  ssh_mprz_init_set_ui(&int_1, 0);
  ssh_mprz_init_set_ui(&int_2, 343);
  ssh_mprz_init_set_si(&int_3, -4982735);

  tm = ssh_time_measure_allocate();
  ssh_time_measure_start(tm);
  for (i = 0; i < 10000; i++)
    {
      context = ssh_asn1_init();
      status =
        ssh_asn1_create_tree(context, &tree,
                             "(sequence (a 1)"
                             "  (sequence (a 2)"
                             "    (integer (1))"
                             "    (integer (2))"
                             "    (sequence (a 3)"
                             "      (integer (3)))))",
                             &int_1, &int_2, &int_3);
      ssh_asn1_free(context);
      if (status != SSH_ASN1_STATUS_OK)
        ssh_fatal("error: (8, 1) %d.\n", status);
    }

  ssh_time_measure_stop(tm);
  printf("%d tree creations in %f seconds\n",
         i,
         (double)
         ssh_time_measure_get(tm, SSH_TIME_GRANULARITY_MILLISECOND)/1000.0);



  context = ssh_asn1_init();
  ssh_asn1_create_tree(context, &tree,
                       "(sequence (a 1)"
                       "  (sequence (a 2)"
                       "    (integer (1))"
                       "    (integer (2))"
                       "    (sequence (a 3)"
                       "      (integer (3)))))",
                       &int_1, &int_2, &int_3);

  ssh_time_measure_reset(tm);
  ssh_time_measure_start(tm);
  for (i = 0; i < 10000; i++)
    {
      status = ssh_asn1_read_tree(context, tree,
                                  "(sequence (a 1)"
                                  "  (sequence (a 2)"
                                  "    (integer (1))"
                                  "    (integer (2))"
                                  "    (sequence (a 3)"
                                  "      (integer (3)))))",
                                  &int_1, &int_2, &int_3);

      ssh_mprz_clear(&int_1);
      ssh_mprz_clear(&int_2);
      ssh_mprz_clear(&int_3);
      if (status != SSH_ASN1_STATUS_OK)
        ssh_fatal("error: (8, 2) %d.\n", status);
    }

  ssh_time_measure_stop(tm);
  printf("%d tree reads in %f seconds\n",
         i,
         (double)
         ssh_time_measure_get(tm, SSH_TIME_GRANULARITY_MILLISECOND)/1000.0);
  ssh_time_measure_free(tm);

  ssh_asn1_free(context);

  ssh_mprz_clear(&int_1);
  ssh_mprz_clear(&int_2);
  ssh_mprz_clear(&int_3);
}


int main(void)
{
  if (!ssh_math_library_initialize())
    ssh_fatal("Cannot initialize the math library");

  test();

  verbose = 1;

  printf("\nTest 1.\n\n");
  test_1();
  printf("\nTest 2.\n\n");
  test_2();
  printf("\nTest 3.\n\n");
  test_3();
  printf("\nTest 4.\n\n");
  test_4();
  printf("\nTest 5.\n\n");
  test_5();
  printf("\nTest 6.\n\n");
  test_6();
  printf("\nTest 7.\n\n");
  test_7();
  printf("\nTest 8.\n\n");
  test_8();

  printf("\nEnd.\n");
  ssh_math_library_uninitialize();
  ssh_util_uninit();
  exit(0);
}
