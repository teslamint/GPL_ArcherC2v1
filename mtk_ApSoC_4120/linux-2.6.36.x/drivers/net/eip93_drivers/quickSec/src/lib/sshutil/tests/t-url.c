/*
  File: t-url.c

  Description:
        Regression tests for URL and HTTP Post encoding and decoding.

  Copyright:
        Copyright (c) 2002, 2003, 2004 SFNT Finland Oy.
        All rights reserved.
*/

#include "sshincludes.h"
#include "sshregression.h"

#include "sshurl.h"

typedef struct TUrlEncDecRec
{
  const unsigned char *input;
  const unsigned char *decoded;
  const unsigned char *encoded;
} TUrlEncDec;

static struct TUrlEncDecRec encoding_tests[] = {
  { "fully safe string", "fully safe string", "fully%20safe%20string" },
  { "fully%20safe%20string", "fully safe string", "fully%20safe%20string" },
  { "safe%20chars%20%2d%28%29", "safe chars -()", "safe%20chars%20-()" },
  { "unsafe %3a%3d%3e", "unsafe :=>", "unsafe%20%3a%3d%3e" }
};

static Boolean test_encoding(void)
{
  unsigned char *a;
  unsigned char *b;
  size_t len, i;
  Boolean tv = TRUE;

  for (i = 0; i < sizeof(encoding_tests) / sizeof(encoding_tests[0]); i++)
    {
      b = ssh_url_data_decode(encoding_tests[i].input,
                              strlen(encoding_tests[i].input),
                              &len);

      if (encoding_tests[i].decoded == NULL)
        {
          if (b) tv = FALSE;
        }
      else
        {
          if (b)
            {
              if (memcmp(b, encoding_tests[i].decoded, len) != 0)
                tv = FALSE;
            }
          else
            tv = FALSE;
        }

      if (!tv)
        {
          ssh_free(b);
          break;
        }

      a = ssh_url_data_encode(b, len, &len);
      ssh_free(b);

      if (strcmp((char *)a, (char *)encoding_tests[i].encoded) != 0)
        tv = FALSE;

      ssh_free(a);
      if (!tv)
        break;
    }

  return tv;
}

typedef struct TUrlAuthRec
{
  const unsigned char *authority;
  const unsigned char *user;
  const unsigned char *pass;
  const unsigned char *host;
  const unsigned char *port;
  SshUrlError expected;
} TUrlAuth;

static struct TUrlAuthRec authority_tests[] =
  {
    { "hel.fi.ssh.com",
      NULL, NULL, "hel.fi.ssh.com", NULL, SSH_URL_OK },
    { "lastulevy:80",
      NULL, NULL, "lastulevy", "80", SSH_URL_OK },
    { "tmo@lastulevy",
      "tmo", NULL, "lastulevy", NULL, SSH_URL_OK },
    { "tmo:foobar@lastulevy",
      "tmo", "foobar", "lastulevy", NULL, SSH_URL_OK },
    { "tmo@lastulevy:80",
      "tmo", NULL, "lastulevy", "80", SSH_URL_OK },
    { "tmo:foo@lastulevy:80",
      "tmo", "foo", "lastulevy", "80", SSH_URL_OK },
    { "10.1.10.1",
      NULL, NULL, "10.1.10.1", NULL, SSH_URL_OK },
    { "[2001:670:83:109:202:b3ff:fe8a:fbb9]",
      NULL, NULL, "[2001:670:83:109:202:b3ff:fe8a:fbb9]", NULL, SSH_URL_OK },
    { "[2001:670:83:109:202:b3ff:fe8a:fbb9]:80",
      NULL, NULL, "[2001:670:83:109:202:b3ff:fe8a:fbb9]", "80", SSH_URL_OK },
    { "tmo@[2001:670:83:109:202:b3ff:fe8a:fbb9]:80",
      "tmo", NULL, "[2001:670:83:109:202:b3ff:fe8a:fbb9]", "80", SSH_URL_OK },
    { "tmo:foo@[2001:670:83:109:202:b3ff:fe8a:fbb9]:80",
      "tmo", "foo", "[2001:670:83:109:202:b3ff:fe8a:fbb9]", "80", SSH_URL_OK },
  };

#define AUTH_DATA_CHECK(e, u, a, h, p, r)               \
do {                                                    \
  if (e.user) {                                         \
    if (!u || strcmp((char *) e.user, (char *) u)) { r = FALSE; break; }  \
  }                                                     \
  if (e.pass) {                                         \
    if (!a || strcmp((char *) e.pass, (char *) a)) { r = FALSE; break; }  \
  }                                                     \
  if (e.host) {                                         \
    if (!h || strcmp((char *) e.host, (char *) h)) { r = FALSE; break; }  \
  }                                                     \
  if (e.port) {                                         \
    if (!p || strcmp((char *) e.port, (char *) p)) { r = FALSE; break; }  \
  }                                                     \
} while (0)

static Boolean test_authority_parse(void)
{
  Boolean tv = TRUE;
  int i;
  SshUrlError rv;
  unsigned char *user, *pass, *host, *port;

  for (i = 0; i < sizeof(authority_tests) / sizeof(authority_tests[0]); i++)
    {
      rv = ssh_url_parse_authority(authority_tests[i].authority,
                                   &user, &pass, &host, &port);

      if (rv == authority_tests[i].expected)
        {
          AUTH_DATA_CHECK(authority_tests[i], user, pass, host, port, tv);
        }
      else
        {
          tv = FALSE;
        }

      ssh_free(user);
      ssh_free(pass);
      ssh_free(host);
      ssh_free(port);

      if (!tv)
        break;
    }
  return tv;
}

static Boolean test_authority_construct(void)
{
  Boolean tv = TRUE;
  int i;
  SshUrlError rv;
  unsigned char *authority;

  for (i = 0; i < sizeof(authority_tests) / sizeof(authority_tests[0]); i++)
    {
      rv = ssh_url_construct_authority(authority_tests[i].user,
                                       authority_tests[i].pass,
                                       authority_tests[i].host,
                                       authority_tests[i].port,
                                       &authority);
      if (rv == authority_tests[i].expected)
        {
          if (strcmp((char *)authority_tests[i].authority, (char *)authority))
            tv = FALSE;
        }
      else
        {
          tv = FALSE;
        }

      ssh_free(authority);
      if (!tv)
        break;
    }
  return tv;
}

static Boolean
key_entry_test(SshUrlQuery q,
               const unsigned char *k, size_t k_len,
               const unsigned char *v, size_t v_len)
{
  SshUrlEntry e;
  const unsigned char *data;
  size_t len;

  e = ssh_url_entry_create(k, k_len, v, v_len);
  if (e)
    {
      data = ssh_url_entry_key(e, &len);
      if (len != k_len)
        goto failed;
      if (memcmp(data, k, k_len))
        goto failed;

      data = ssh_url_entry_value(e, &len);
      if (len != v_len)
        goto failed;
      if (memcmp(data, v, v_len))
        goto failed;

      if (q)
        ssh_url_query_entry_insert(q, e);
      else
        ssh_url_entry_destroy(e);
      return TRUE;

    failed:
      ssh_url_entry_destroy(e);
    }
  return FALSE;

}

static Boolean test_entry(void)
{
  if (!key_entry_test(NULL, NULL, 0, NULL, 0))
    return FALSE;
  if (!key_entry_test(NULL, "", 0, "", 0))
    return FALSE;
  if (!key_entry_test(NULL, "number", 6, "", 0))
    return FALSE;
  if (!key_entry_test(NULL, "number", 6, "123456", 6))
    return FALSE;
  if (!key_entry_test(NULL, NULL, 0, "123456", 6))
    return FALSE;

  return TRUE;
}

static Boolean test_query(void)
{
  SshUrlQuery q;

  if ((q = ssh_url_query_allocate()) != NULL)
    {
      ssh_url_query_free(q);
      return TRUE;
    }
  return FALSE;
}

typedef struct TUrlEntryRec {
  unsigned char *key;
  unsigned char *value;
} *TUrlEntry;

static struct TUrlEntryRec entry_tests[] = {
  { "", "" },
  { "kukkuu", "" },
  { "kukkuu", "reset" },
  { "kukkuu", "bang!" },
  { "kukkuu", "reset" },
  { "reset", "" }
};

static Boolean test_query_entry(void)
{
  SshUrlQuery q;
  SshUrlEntry e;

  if ((q = ssh_url_query_allocate()) != NULL)
    {
      int i = 0, n = 0;
      const unsigned char *data;
      size_t len;

      for (i = 0; i < sizeof(entry_tests) / sizeof(entry_tests[0]); i++)
        {
          key_entry_test(q,
                         entry_tests[i].key,
                         strlen((char *)entry_tests[i].key),
                         entry_tests[i].value,
                         strlen((char *)entry_tests[i].value));
        }
      /* Check that we will traverse correct number of entries */
      for (n = 0, e = ssh_url_query_enumerate_start(q);
           e;
           n++, e = ssh_url_query_enumerate_next(q, e))
        {
          data = ssh_url_entry_key(e, &len);
          if (strcmp((char *)data, (char *)entry_tests[n].key))
            goto failed;
          data = ssh_url_entry_value(e, &len);
          if (strcmp((char *)data, (char *)entry_tests[n].value))
            goto failed;
        }

      if (n != i)
        goto failed;

      e = ssh_url_query_get_entry(q, "reset", 5);
      if (e == NULL)
        goto failed;

      e = ssh_url_query_get_next_same_entry(q, e);
      if (e)
        goto failed;

      e = ssh_url_query_get_entry(q, "kukkuu", 6);
      if (e == NULL)
        goto failed;

      i = 0;
      while ((e = ssh_url_query_get_next_same_entry(q, e)) != NULL)
        i++;

      if (i != 3)
        goto failed;

      /* Test removal */
      e = ssh_url_query_get_entry(q, "reset", 5);
      if (e == NULL)
        goto failed;
      ssh_url_query_entry_delete(q, e);
      ssh_url_entry_destroy(e);
      e = ssh_url_query_get_entry(q, "reset", 5);
      if (e != NULL)
        goto failed;

      e = ssh_url_query_get_entry(q, "kukkuu", 6);
      if (e == NULL)
        goto failed;
      ssh_url_query_entry_delete(q, e);
      ssh_url_entry_destroy(e);
      e = ssh_url_query_get_entry(q, "kukkuu", 6);
      if (e == NULL)
        goto failed;
      i = 0;
      while ((e = ssh_url_query_get_next_same_entry(q, e)) != NULL)
        i++;
      if (i != 2)
        goto failed;

      ssh_url_query_free(q);
      return TRUE;

    failed:
      ssh_url_query_free(q);
    }

  return FALSE;
}

typedef struct TUrlBasicRec {
  const unsigned char *url;
  const unsigned char *scheme;
  const unsigned char *authority;
  const unsigned char *path;
  const unsigned char *fragment;
  SshUrlError expected;
} *TUrlBasic;

static struct TUrlBasicRec url_valid[] = {
  { "http://www.ssh.fi/testing/host",
    "http", "www.ssh.fi", "testing/host", NULL,
    SSH_URL_OK },
  { "http://[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]/testing/host",
    "http", "[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]", "testing/host", NULL,
    SSH_URL_OK},
  { "file:///testing/host",
    "file",  NULL, "testing/host", NULL,
    SSH_URL_OK},
  { "file://netbsd",
    "file", "netbsd", NULL, NULL,
    SSH_URL_OK },
  { "file:/netbsd",
    "file", "/netbsd", NULL, NULL,
    SSH_URL_OK },
  { "http:tmo@ssh.fi",
    "http", "tmo@ssh.fi", NULL, NULL,
    SSH_URL_OK },
  { "http://quote.yahoo.com/?",
    "http", "quote.yahoo.com", NULL, NULL,
    SSH_URL_OK },
  { "http://quote.yahoo.com/q?s=nok&d=v1",
    "http", "quote.yahoo.com", NULL, NULL,
    SSH_URL_OK },
  { "ldap://CN=admin:a6m1n@server.ssh.com/DC=COM??sub?(objectclass=*)",
    "ldap", "CN=admin:a6m1n@server.ssh.com", NULL, NULL,
    SSH_URL_OK }
};

static struct TUrlBasicRec url_invalid[] = {
  { "http//www.ssh.fi/testing/host",
    NULL, NULL, NULL, NULL,
    SSH_URL_INVALID_ENCODING },
  { "http//www.ssh.fi:80/testing/host",
    NULL, NULL, NULL, NULL,
    SSH_URL_INVALID_ENCODING },
  { "http//tmo:foo@www.ssh.fi:80/testing/host",
    NULL, NULL, NULL, NULL,
    SSH_URL_INVALID_ENCODING },
  { "http//www.ssh.fi:80/testing/host",
    NULL, NULL, NULL, NULL,
    SSH_URL_INVALID_ENCODING },
  { "",
    NULL, NULL, NULL, NULL,
    SSH_URL_INVALID_ENCODING },
};

static Boolean test_get_parse(TUrlBasic tests, size_t ntests)
{
  Boolean tv = TRUE;
  int i;
  SshUrlError rv;
  unsigned char *scheme, *authority, *path, *fragment;
  SshUrlQuery query;

  for (i = 0; i < ntests; i++)
    {
      rv = ssh_url_parse_get(tests[i].url,
                             &scheme, &authority, &path, &query, &fragment,
                             FALSE);

      if (rv == tests[i].expected)
        {
          ;
        }
      else
        {
          tv = FALSE;
        }

      ssh_free(scheme);
      ssh_free(authority);
      ssh_free(path);
      ssh_free(fragment);
      if (query)
        ssh_url_query_free(query);

      if (!tv)
        break;
    }
  return tv;
}

typedef struct TUrlQueryItemRec {
  const unsigned char *key;
  const unsigned char *value;
} *TUrlQueryItem;

typedef struct TUrlQueryRec {
  const unsigned char *url;
  const unsigned char *path;
  SshUrlError expected;
  struct TUrlQueryItemRec table[10];
} *TUrlQuery;

static struct TUrlQueryRec url_query_valid[] = {
  { "http:tmo@ssh.fi", "tmo@ssh.fi",
    SSH_URL_OK, {{ NULL, NULL }}},

  { "http:///foo?a=b", "foo",
    SSH_URL_OK,
    { { "a", "b" } } },

  { "http:///foo?a=b&c=d", "foo",
    SSH_URL_OK,
    { { "a", "b" }, { "c", "d" } } },

  { "http:///aksjdklasjdlkasjdlkasjdkla?kukkuu=reset",
    "aksjdklasjdlkasjdlkasjdkla",
    SSH_URL_OK,
    { { "kukkuu", "reset" } } },

  { "http:///foo?&a=b&c=d", "foo", SSH_URL_OK,
    { { "a", "b" }, { "c", "d" } } },

  { "http:///foo?a=b&&c=d", "foo", SSH_URL_OK,
    { { "a", "b" }, { "c", "d" } } },

  { "http:///foo?a=b&c=d&", "foo", SSH_URL_OK,
    { { "a", "b" }, { "c", "d" } } },

  { "http://foo/?a=b&c=d&e=f", "",
    SSH_URL_OK,
    { { "a", "b" }, { "c", "d" }, { "e", "f" } } },

  { "http:///%20%21%22?kukkuu=reset&zappa=bar", "%20%21%22",
    SSH_URL_OK,
    { { "kukkuu", "reset" }, { "zappa", "bar" } } },

  { "http:%20%21\"?kukk%75u=re%73et&zap%70a=b%61r", "%20%21\"",
    SSH_URL_OK,
    { { "kukkuu", "reset" }, { "zappa", "bar" } } },

  { "http:///fo%3do?kuk%3dk%75u=re%73et&zap%70a=b%61r%3dfoo", "fo%3do",
    SSH_URL_OK,
    { { "kuk=kuu", "reset" }, { "zappa", "bar=foo" } } },

  { "http:///fo%26o?kuk%26k%75u=re%73et&zap%70a=b%61r%26foo", "fo%26o",
    SSH_URL_OK,
    { { "kuk&kuu", "reset" }, { "zappa", "bar&foo" } } },

  { "http:///foo?name=Tero%20&name=T%20&name=Kivinen", "foo",
    SSH_URL_OK,
    {
      { "name", "Tero " },
      { "name", "T " },
      { "name", "Kivinen" } } },

  { "http:///foo?na%6de=Tero%20&nam%65=T%20&n%61me=Kivinen", "foo",
    SSH_URL_OK,
    {
      { "name", "Tero " },
      { "name", "T " },
      { "name", "Kivinen" } } },

  { "http:///foo?na%6de=Tero%20&nam%65=T%20&n%61me=Kivinen&bar=zappa", "foo",
    SSH_URL_OK,
    {
      { "name", "Tero " },
      { "name", "T " },
      { "name", "Kivinen" },
      { "bar", "zappa" } } },

  { "http:///foo?first+name=Tero+Tapani&Last%2bName=Kivinen%2b%2b", "foo",
    SSH_URL_OK,
    { { "first name", "Tero Tapani" }, { "Last+Name", "Kivinen++" } }}
};

static struct TUrlQueryRec url_query_invalid[] = {
#if 0
  { "http:///fo%xx?a=b&c=d", "/fo%xx", SSH_URL_INVALID_ENCODING,
    { { "a", "b" }, { "c", "d" } } },
  { "http:///fo%3?a=b&c=d", "/fo%3", SSH_URL_INVALID_ENCODING,
    { { "a", "b" }, { "c", "d" } } },
  { "http:///fo%?a=b&c=d", "/fo%", SSH_URL_INVALID_ENCODING,
    { { "a", "b" }, { "c", "d" } } },
#endif
  { "http:///foo?a%xx=b&c=d", "foo", SSH_URL_INVALID_ENCODING,
    { { "a%xx", "b" }, { "c", "d" } } },
  { "http:///foo?a%3=b&c=d", "foo", SSH_URL_INVALID_ENCODING,
    { { "a%3", "b" }, { "c", "d" } } },
  { "http:///foo?a%=b&c=d", "foo", SSH_URL_INVALID_ENCODING,
    { { "a%", "b" }, { "c", "d" } } },
  { "http:///foo?a=b&c=%xxd", "foo", SSH_URL_INVALID_ENCODING,
    { { "a", "b" }, { "c", "%xxd" } } },
  { "http:///foo?a=b&c=%3qd", "foo", SSH_URL_INVALID_ENCODING,
    { { "a", "b" }, { "c", "%3qd" } } },
  { "http:///foo?a=b&c=%qd", "foo", SSH_URL_INVALID_ENCODING,
    { { "a", "b" }, { "c", "%qd" } } },
  { "http:///foo?a=b&c=d%", "foo", SSH_URL_INVALID_ENCODING,
    { { "a", "b" }, { "c", "d%" } } },
  { "http:///foo?a=b&c=d%xx", "foo", SSH_URL_INVALID_ENCODING,
    { { "a", "b" }, { "c", "d%xx" } } },
  { "http:///foo?a=b&c=d%3", "foo", SSH_URL_INVALID_ENCODING,
    { { "a", "b" }, { "c", "d%3" } } },
};

static Boolean
check_path_and_query(TUrlQuery test,
                     unsigned char *path,
                     SshUrlQuery query)
{
  int j;
  Boolean tv = TRUE;

  if (query == NULL)
    return tv;

  if (strcmp((char *)path, (char *)test->path))
    tv = FALSE;
  else
    {
      SshUrlEntry entry;

      for (j = 0, entry = ssh_url_query_enumerate_start(query);
           entry;
           j++, entry = ssh_url_query_enumerate_next(query, entry))
        {
          const unsigned char *key, *val;
          size_t len;

          key = ssh_url_entry_key(entry, &len);

          if (strcmp((char *)key, (char *)test->table[j].key))
            tv = FALSE;
          if (tv)
            {
              val = ssh_url_entry_value(entry, &len);
              if (strcmp((char *)val, (char *)test->table[j].value))
                tv = FALSE;
            }
        }
    }
  return tv;
}

static Boolean test_get_parse_query(TUrlQuery tests, size_t ntests)
{
  int i;
  Boolean tv = TRUE;
  unsigned char *path;
  SshUrlQuery query;
  SshUrlError rv;

  for (i = 0; tv && i < ntests; i++)
    {
      rv = ssh_url_parse_get(tests[i].url,
                             NULL, NULL, &path, &query, NULL, FALSE);
      if (rv == tests[i].expected)
        {
          if (rv == SSH_URL_OK)
            {
              tv = check_path_and_query(&tests[i], path, query);
              ssh_url_query_free(query);
              ssh_free(path);
            }
        }
      else
        {
          tv = FALSE;
        }
    }

  return tv;
}


static Boolean test_get_encode_decode(TUrlQuery tests, size_t ntests)
{
  unsigned char *url, *path;
  SshUrlError rv;
  Boolean tv = TRUE;
  SshUrlQuery query;
  SshUrlEntry entry;
  const char *k, *v;
  size_t k_len, v_len, i, j;

  for (i = 0; i < ntests; i++)
    {
      query = ssh_url_query_allocate();

      for (j = 0;
           tests[i].table[j].key;
           j++)
        {
          k = tests[i].table[j].key; k_len = strlen(k);
          if ((v = tests[i].table[j].value) != NULL)
            v_len = strlen(v);
          else
            v_len = 0;

          entry = ssh_url_entry_create(k, k_len, v, v_len);
          ssh_url_query_entry_insert(query, entry);
        }

      rv = ssh_url_construct_get("http", NULL, tests[i].path, query, NULL,
                                 &url);

      ssh_url_query_free(query);

      rv = ssh_url_parse_get(url,
                             NULL, NULL, &path, &query, NULL, FALSE);
      ssh_free(url);
      if (rv == SSH_URL_OK)
        {
          tv = check_path_and_query(&tests[i], path, query);
          ssh_url_query_free(query);
          ssh_free(path);
        }
    }
  return tv;
}

int main(int ac, char **av)
{
  ssh_regression_init(&ac, &av,
                      "URL and HTTP POST construction and parsing",
                      "ipsec-support@ssh.com");

  ssh_regression_section("Utility functions");

  SSH_REGRESSION_TEST("Transport encoding", test_encoding, ());
  SSH_REGRESSION_TEST("Authority parsing", test_authority_parse, ());
  SSH_REGRESSION_TEST("Authority construct", test_authority_construct, ());
  SSH_REGRESSION_TEST("Entry create, values and free", test_entry, ());
  SSH_REGRESSION_TEST("Query create and free", test_query, ());
  SSH_REGRESSION_TEST("Query entry management", test_query_entry, ());

  ssh_regression_section("URL parsing");

  SSH_REGRESSION_TEST("Valid formats",
                      test_get_parse,
                      (url_valid,
                       sizeof(url_valid) / sizeof(url_valid[0])));


  SSH_REGRESSION_TEST("Invalid formats",
                      test_get_parse,
                      (url_invalid,
                       sizeof(url_invalid) / sizeof(url_invalid[0])));

  SSH_REGRESSION_TEST("Valid formats with queries",
                      test_get_parse_query,
                      (url_query_valid,
                       sizeof(url_query_valid) / sizeof(url_query_valid[0])));

  SSH_REGRESSION_TEST("Invalid formats with queries",
                      test_get_parse_query,
                      (url_query_invalid,
                       sizeof(url_query_invalid) /
                       sizeof(url_query_invalid[0])));

  ssh_regression_section("URL construction");

  SSH_REGRESSION_TEST("Encode and decode compatibility",
                      test_get_encode_decode,
                      (url_query_valid,
                       sizeof(url_query_valid) / sizeof(url_query_valid[0])));

  ssh_regression_section("POST parsing");

  ssh_regression_section("POST construction");

  ssh_regression_finish();
  return 0;
}
