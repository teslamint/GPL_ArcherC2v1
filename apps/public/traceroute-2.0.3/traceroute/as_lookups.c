/*
    Copyright (c)  2006		    Dmitry K. Butskoy
				    <buc@citadel.stu.neva.ru>
    License:  GPL		

    See COPYING for the status of this software.
*/

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <errno.h>
#include <linux/types.h>
#include <linux/errqueue.h>

#include "traceroute.h"


#define DEF_RADB_SERVER		"whois.radb.net"
#define DEF_RADB_SERVICE	"whois"


static sockaddr_any ra_addr = {{ 0, }, };
static char ra_buf[256] = { 0, };


const char *get_as_path (const char *query) {
	int sk, n;
	FILE *fp;
	char buf[1024];
	int prefix = 0, best_prefix = 0;
	size_t ra_buf_len = sizeof (ra_buf) - 1;


	if (!ra_addr.sa.sa_family) {
	    const char *server, *service;
	    struct addrinfo *res;
	    int ret;

	    server = getenv ("RA_SERVER");
	    if (!server)  server = DEF_RADB_SERVER;

	    service = getenv ("RA_SERVICE");
	    if (!service)  service = DEF_RADB_SERVICE;


	    ret = getaddrinfo (server, service, NULL, &res);
	    if (ret) {
		fprintf (stderr, "%s/%s: %s\n", server, service,
						    gai_strerror(ret));
		exit (2);
	    }	

	    memcpy (&ra_addr, res->ai_addr, res->ai_addrlen);

	    freeaddrinfo (res);
	}


	sk = socket (ra_addr.sa.sa_family, SOCK_STREAM, 0);
	if (sk < 0)  error ("socket");

	if (connect (sk, &ra_addr.sa, sizeof (ra_addr)) < 0)
		goto  err_sk;

	n = snprintf (buf, sizeof (buf), "%s\r\n", query);

	if (write (sk, buf, n) < n)
		goto err_sk;

	fp = fdopen (sk, "r");
	if (!fp)  goto err_sk;


	strncpy (ra_buf, "*", ra_buf_len);

	while (fgets (buf, sizeof (buf), fp) != NULL) {

	    if (!strncmp (buf, "route:", sizeof ("route:") - 1) ||
		!strncmp (buf, "route6:", sizeof ("route6:") - 1)
	    ) {
		char *p = strchr (buf, '/');

		if (p)  prefix = strtoul (++p, NULL, 10);
		else  prefix = 0;	/*  Hmmm...  */

	    }
	    else if (!strncmp (buf, "origin:", sizeof ("origin:") -1)) {
		char *p, *as;

		p = buf + (sizeof ("origin:") - 1);

		while (isspace (*p))  p++;
		as = p;
		while (!isspace (*p))  p++;
		*p = '\0';

		if (prefix > best_prefix) {
		    best_prefix = prefix;

		    strncpy (ra_buf, as, ra_buf_len);
		}
		else if (prefix == best_prefix) {
		    char *q = strstr (ra_buf, as);

		    if (!q || (*(q += strlen (as)) != '\0' && *q != '/')) {
			strncat (ra_buf, "/", ra_buf_len);
			strncat (ra_buf, as, ra_buf_len);
		    }
		}
		/*  else just ignore it   */
	    }
	}

	fclose (fp);

	return ra_buf;


err_sk:
	close (sk);
	return "!!";
}
