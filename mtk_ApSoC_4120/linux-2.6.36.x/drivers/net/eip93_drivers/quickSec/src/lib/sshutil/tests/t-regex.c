/*

  t-regex.c

  Author: Antti Huima <huima@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All rights reserved.

  Created Tue Sep  7 12:52:02 1999.

  */

#include "sshincludes.h"
#include "sshdebug.h"
#include "sshregex.h"
#include "sshregression.h"
#include "sshdlex.h"

/* This test program considers memory allocation errors as succesful tests so
   that it can be used in conjunction with tests based on deliberately failing
   memory allocators. */

typedef struct {
  const char *regex;
  const char *text;
  const char *first_submatch;
  SshRegexSyntax syntax;
  Boolean prefix_only;
} SshRegexTestItem;

static SshRegexTestItem tests[] =
{
  { "Literal match" },
  { "(abcdef)", "abcdefghijklmn", "abcdef" },
  { "(abcdef)", "123456789abcdefghijklmn", "abcdef" },
  { "(abcdef)", "123012301230123abcdef", "abcdef" },
  { "(abcdef)", "123012301230123abcdex", NULL },

  { "Single-level repetition" },
  { "(a*(goo)b*)", "12345678aaaagoobbbb", "aaaagoobbbb" },
  { "foo({bar}*)", "viuvaufoobarbarbar", "barbarbar" },
  { "(a+b+c+)", "zzzaaabbbbcc", "aaabbbbcc" },
  { "(a+b+c+)", "zzzaaaqqqqcc", NULL },
  { "(aa+b+c+)", "zzzabbbcc", NULL },
  { "(aa+b+c+)", "zzzaabbbcc", "aabbbcc" },

  { "Multiple repetitions" },
  { "(a(b(c+))+)", "abccccbcbccc", "abccccbcbccc" },
  { "(a(b(c+))+)", "abccccbbcc", "abcccc" },
  { "(a(b(c+))+)", "accccbbcc", NULL },

  { "Bounded repetitions" },
  { "a(a/3,5/)", "bbbaaaaaaaa", "aaaaa" },
  { "a(a/3,/)", "bbbaaaaaaaa", "aaaaaaa" },
  { "a(a/0,5/)", "bbbaaaaaaaa", "aaaaa" },
  { "a(a/,3/)", "bbbaaaaaaaa", "aaa" },
  { "a(a/3/)", "bbbaaaaaaaa", "aaa" },

  { "Lazy operators" },
  { "a(a/3,5/?)", "bbbaaaaaaaa", "aaa" },
  { "foo({bar}+?)", "foobarbarbar", "bar" },
  { "foo({bar}+?)x", "foobarbarbarx", "barbarbar" },
  { "(viua*?)", "xxviuaaaa", "viu" },
  { "(viua*?)$", "xxviuaaaa", "viuaaaa" },

  { "Anchoring" },
  { "(.foo)$", "1foo2foo3foo", "3foo" },
  { "^(.foo)", "foo2foo3foo", NULL },
  { "^(.foo)", "2foo3foo4foo", "2foo" },
  { "(^$)", "", "" },
  { "^$", "x", NULL },

  { "Disjunctions" },
  { "(apple|pie|banana)", "I like a banana", "banana" },
  { "(apple|pie|banana)", "I like an apple", "apple" },
  { "(fi|firs|first)", "I am first", "fi" },
  { "(first|firs|fi)", "I am first", "first" },
  { "({a|b}+)", "zop abababba", "abababba" },
  { "({a|foo}+)", "xxxfooafooaaafooa", "fooafooaaafooa" },

  { "Character sets" },
  { "([a:z]+)", "GGabcdefg", "abcdefg" },
  { "([a:z-d]+)", "GGabcdefg", "abc" },
  { "([-x]+)", "abcdefxhi", "abcdef" },
  { "([~d-4]+)", "aaa1234567", "123" },
  { "([-~d]+)", "123456foobar123456", "foobar" },
  { "(~w+)", "       what is this     ", "what" },

  { "Boundaries" },
  { "(~<foo.*)", "viufoo barfoo foobar", "foobar" },
  { "(~<[a:z]+foo~>)", "asdfasdffoozz viufoo", "viufoo" },
  { "(~bfoo[a:z]~b)", "goofoo foobaz fooq fooxxx", "fooq" },

  { "Buggy regular expressions (should fail to compile)" },
  { "!foo|", "" },
  { "!(foo|)bar", "" },
  { "!{foo|}bar", "" },
  { "!{|}bar" , "" },
  { "!*", "" },
  { "!(", "" },
  { "!**", "" },
  { "![a:z", "" },

  { "Prefix Matching", NULL, NULL, SSH_REGEX_SYNTAX_SSH, TRUE },
  { "^(foo)bar", "foob", "foo" },
  { "^foobar", "fooz", NULL },
  { "^a+b+c+", "bc", NULL },
  { "^(g)a+b+", "gaaaaaaa", "g" },
  { "^(gor|ba|zaa)viuvau", "zaaviu", "zaa" },
  { "^(gor|ba|zaa)viuvau", "gbaviu", NULL },
  { "^(gor|ba|zaa)viuvau", "zaavix", NULL },

  { "ZSH File Globs", NULL, NULL, SSH_REGEX_SYNTAX_ZSH_FILEGLOB, FALSE },
  { "foobar", "foobar", "" },
  { "foo*bar", "foozazzazabar", "" },
  { "*", "goz", "" },
  { "*", ".goz", NULL },
  { "foo/*/garbage", "foo/viuvau/garbage", "" },
  { "foo/*/garbage", "foo/viuvau/another/garbage", NULL },
  { "foo/*/garbage", "foo/.dotted/garbage", NULL },
  { "foo/**/garbage", "foo/.dotted/garbage", NULL },
  { "foo/**/garbage", "foo/nondotted/.dotted/garbage", NULL },
  { "**/baz", "baz", "" },
  { "**/baz", "/dir1/dir2/dir3/baz", "" },
  { "foo/**/garbage", "foo/dir1/dir2/dir3/garbage", "" },
  { "**goo", "/goo", NULL },
  { "**goo", "/bar/goo", NULL },
  { "**/**/**/foobar", "foobar", "" },
  { "**/**/**/foobar", "1/2/3/foobar", "" },
  { "foo.[ch]", "foo.c", "" },
  { "foo.[ch]", "foo.h", "" },
  { "foo.[ch]", "foo.a", NULL },
  { "foo.[^ch]", "foo.a", "" },
  { "foo.[^ch]", "foo.c", NULL },
  { "foo.[1-9]", "foo.1", "" },
  { "foo.[1-9]", "foo.x", NULL },

  { "ZSH File Globs With Prefix Matching", NULL, NULL,
    SSH_REGEX_SYNTAX_ZSH_FILEGLOB, TRUE },
  { "foobar", "foob", "" },
  { "foo*bar", "foozazza", "" },
  { "*", "goz", "" },
  { "*", ".goz", NULL },
  { "foo/*/garbage", "foo/viuvau/garb", "" },
  { "foo/*/garbage", "foo/viuv", "" },
  { "foo/*/garbage", "foo/.dotted/", NULL },
  { "foo/**/garbage", "foo/.dotted/", NULL },
  { "**/baz", "ba", "" },
  { "**/baz", "/dir1/dir2/dir3", "" },
  { "foo/**/garbage", "foo/dir1/dir2/d", "" },
  { "**goo", "/goo", NULL },
  { "**goo", "/bar/goo", NULL },
  { "**/**/**/foobar", "fooba", "" },
  { "**/**/**/foobar", "1/2/3/foo", "" },

  { "EGrep syntax", NULL, NULL, SSH_REGEX_SYNTAX_EGREP, FALSE },
  { "([a-z]+)", "GGabcdefg", "abcdefg" },
  { "([a-ce-z]+)", "GGabcdefg", "abc" },
  { "([^x]+)", "abcdefxhi", "abcdef" },
  { "([0-9]+)", "aaa123Q567", "123" },
  { "([[:digit:]]+)", "aaa123Q567", "123" },
  { "([^0-9]+)", "123456foobar123456", "foobar" },
  { "(\\w+)", "       what is this     ", "what" },
  { "(.foo)$", "1foo2foo3foo", "3foo" },
  { "^(.foo)", "foo2foo3foo", NULL },
  { "^(.foo)", "2foo3foo4foo", "2foo" },
  { "(^$)", "", "" },
  { "([abc:]+)", "foo:ar", ":a" },
  { "^$", "x", NULL },
};


#define NUM_TESTS ((sizeof(tests) / sizeof(tests[0])))

Boolean do_check(SshRegexContext c, SshRegexTestItem *t,
                 Boolean only_prefix, SshRegexSyntax syntax)
{
  SshRegexMatcher m;
  int from;
  size_t len;
  Boolean passed = FALSE;
  Boolean result;

  /* Exclamation mark denotes that the regular expression must fail to
     compile. */
  if (t->regex[0] == '!')
    {
      m = ssh_regex_create(c, t->regex + 1, syntax);
      if (m != NULL)
        {
          ssh_regex_free(m);
          return FALSE;
        }

      if (ssh_regex_get_compile_error(c) == SSH_REGEX_OUT_OF_MEMORY)
        fprintf(stderr, "[out of memory] ");

      return TRUE;
    }

  m = ssh_regex_create(c, t->regex, syntax);

  if (m == NULL)
    {
      if (ssh_regex_get_compile_error(c) == SSH_REGEX_OUT_OF_MEMORY)
        {
          fprintf(stderr, "[out of memory] ");
          return TRUE;
        }

      fprintf(stderr, "(compile error) ");
      return FALSE;
    }

  result = (only_prefix
            ? ssh_regex_match_cstr_prefix(m, t->text)
            : ssh_regex_match_cstr(m, t->text));

  if (result)
    {
      if (t->first_submatch != NULL)
        {
          if (*(t->first_submatch) == 0)
            {
              passed = TRUE;
            }
          else
            {
              if (ssh_regex_access_submatch(m, 1, &from, &len))
                {
                  if (len == strlen(t->first_submatch) &&
                      !(strncmp(t->first_submatch, t->text + from, len)))
                    {
                      passed = TRUE;
                    }
                }
            }
        }
    }
  else /* No match. */
    {
      if (t->first_submatch == NULL)
        passed = TRUE;
      if (ssh_regex_get_match_error(m) == SSH_REGEX_OUT_OF_MEMORY)
        {
          fprintf(stderr, "[out of memory] ");
          passed = TRUE;
        }
    }
  ssh_regex_free(m);
  return passed;
}

typedef struct SshDLexTestItemRec {
  const char *regexs[8];
  const char *input;
  int tokens[20];
} SshDLexTestItemStruct, *SshDLexTestItem;

SshDLexTestItemStruct dlex_tests[] = {
  { { "a+", "b+", "." }, "aaaxbbbby31", { 1, 3, 2, 3, 3, 3 } },
  { { "[A:Z][a:z]*", " +" }, "Some   CapitalizedWords", { 1, 2, 1, 1 } },
  { { "foo", "fo+" }, "foofoooofoo", { 1, 1, -1 } },
  { { "fo+", "foo" }, "foofoooofoo", { 1, 1, 1 } },
  { { "g(a|b)+", "(zap)", "." }, "gabbagabzapabgab",
    { 1, 1, 2, 3, 3, 1 } },
};

#define NUM_DLEX_TESTS ((sizeof(dlex_tests) / sizeof(dlex_tests[0])))

Boolean dlex_test_one(SshRegexContext c, SshDLexTestItem test)
{
  SshDLexer dlex;
  int n;
  int len, token;
  int x;

  unsigned char *ptr;
  unsigned char *end;

  for (n = 0; test->regexs[n] != NULL; n++);

  dlex = ssh_dlex_create(c, test->regexs, n, SSH_REGEX_SYNTAX_SSH,
                         SSH_DLEX_FIRST_MATCH);

  if (dlex == NULL)
    {
      /* Assume it is an out-of-memory error. */
      fprintf(stderr, "[out of memory - no lexer] ");
      return TRUE;
    }

  ptr = (unsigned char *)(test->input);
  end = ptr + strlen((char *)ptr);

  x = 0;

  while (ptr < end && ssh_dlex_next(dlex, ptr, (int)(end - ptr), &len, &token))
    {
      token++;
#if 0
      fprintf(stderr, "Token %d `%.*s' at `%s'.\n",
              token, len, ptr, ptr);
#endif

      if (token != test->tokens[x])
        return FALSE;


      x++;

      ptr += len;
    }

  if (ptr < end)
    {
      if (ssh_dlex_get_scan_error(dlex) == SSH_REGEX_OUT_OF_MEMORY)
        {
          fprintf(stderr, "[out of memory during scanning] ");
          ssh_dlex_destroy(dlex);
          return TRUE;
        }
    }

  if ((ptr != end) ^ (test->tokens[x] == -1))
    return FALSE;

  ssh_dlex_destroy(dlex);

  return TRUE;
}

void dlex_test(SshRegexContext c)
{
  int i;

  for (i = 0; i < NUM_DLEX_TESTS; i++)
    {
      SSH_REGRESSION_TEST(dlex_tests[i].input, dlex_test_one,
                          (c, &dlex_tests[i]));
    }
}

int main(int argc, char **argv)
{
  int i;
  SshRegexTestItem *t;
  SshRegexContext c;
  Boolean only_prefix = FALSE;
  SshRegexSyntax syntax = SSH_REGEX_SYNTAX_SSH;

  ssh_regression_init(&argc, &argv, "Regular expression utility",
                      "huima@ssh.fi");

  c = ssh_regex_create_context();

  if (c == NULL)
    {
      fprintf(stderr, "Could not allocate the regex context --- no memory.\n");
      return 0;
    }

  for (i = 0; i < NUM_TESTS; i++)
    {
      t = &tests[i];
      if (t->text == NULL)
        {
          ssh_regression_section(t->regex);
          only_prefix = t->prefix_only;
          syntax = t->syntax;
          if (syntax == 0) syntax = SSH_REGEX_SYNTAX_SSH;
          continue;
        }
      SSH_REGRESSION_TEST(t->regex, do_check, (c, t, only_prefix, syntax));
    }

  ssh_regression_section("Dynamic lexer");

  dlex_test(c);

  ssh_regex_free_context(c);
  ssh_regression_finish();

  return 0;
}
