/*
    Copyright (c)  2006		    Dmitry K. Butskoy
				    <buc@citadel.stu.neva.ru>
    License:  GPL		

    See COPYING for the status of this software.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <errno.h>
#include <locale.h>
#include <linux/types.h>
#include <linux/errqueue.h>

/*  XXX: Remove this when things will be defined properly in netinet/ ...  */
#include "flowlabel.h"

#include <clif.h>
#include "version.h"
#include "traceroute.h"

#ifdef CMM_MSG /* Yang Caiyong, 20Jul2012 */
#include <os_msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#endif /* CMM_MSG */

#ifndef ICMP6_DST_UNREACH_BEYONDSCOPE
#ifdef ICMP6_DST_UNREACH_NOTNEIGHBOR
#define ICMP6_DST_UNREACH_BEYONDSCOPE ICMP6_DST_UNREACH_NOTNEIGHBOR
#else
#define ICMP6_DST_UNREACH_BEYONDSCOPE 2
#endif
#endif

#ifndef IPV6_RECVHOPLIMIT
#define IPV6_RECVHOPLIMIT IPV6_HOPLIMIT
#endif


#define MAX_HOPS	255
#define MAX_PROBES	10
#define MAX_GATEWAYS_4	8
#define MAX_GATEWAYS_6	127
#define DEF_HOPS	30
#define DEF_SIM_PROBES	16	/*  including several hops   */
#define DEF_NUM_PROBES	3
#define DEF_WAIT_SECS	5.0
#define DEF_SEND_SECS	0
#define DEF_PACKET_LEN	40
#define MAX_PACKET_LEN	65000
#define DEF_AF		AF_INET
#define NI_IDN    32  /* Convert name from IDN format.  */    

#ifdef CMM_MSG /* Yang Caiyong, 20Jul2012 */
#define AI_IDN    0x0040  /* IDN encode input (assuming it is encoded
                   in the current locale's character set)
                    before looking it up. */

int traceResult = 0;

static int entryCompelete = 0;
static int entryProbes = 0;
static int responseTime = 0;

#endif /* CMM_MSG */

#define __TEXT(X)       #X
#define _TEXT(X)        __TEXT(X)

static char version_string[] = "Modern traceroute for Linux, "
				"version " _TEXT(VERSION) ", " __DATE__
				"\nCopyright (c) 2006  Dmitry Butskoy, "
				"  License: GPL";
static int debug = 0;
static unsigned int first_hop = 0;
static unsigned int max_hops = DEF_HOPS;
static unsigned int sim_probes = DEF_SIM_PROBES;
static unsigned int probes_per_hop = DEF_NUM_PROBES;

static char **gateways = NULL;
static int num_gateways = 0;
static unsigned char *rtbuf = NULL;
static size_t rtbuf_len = 0;

static int dontfrag = 0;
static int noresolve = 0;
static int as_lookups = 0;
static unsigned int dst_port_seq = 0;
static unsigned int tos = 0;
static unsigned int flow_label = 0;
static int noroute = 0;
static unsigned int packet_len = DEF_PACKET_LEN;
static double wait_secs = DEF_WAIT_SECS;
static double send_secs = DEF_SEND_SECS;

static sockaddr_any dst_addr = {{ 0, }, };
static char *dst_name = NULL;
static char *device = NULL;
static sockaddr_any src_addr = {{ 0, }, };

static tr_ops *ops = &udp_ops;

static int af = 0;

static probe *probes = NULL;
static unsigned int num_probes = 0;


static void ex_error (const char *format, ...) {
	va_list ap;
#ifdef CMM_MSG /* Yang Caiyong, 07Aug2012 */
	char err[1024] = {0};
#endif /* CMM_MSG */

	va_start (ap, format);
#ifdef CMM_MSG /* Yang Caiyong, 07Aug2012 */
	vsprintf(err, format, ap);
	send_result(TRACE_COMPLETE, 0, "0.0.0.0", err);
#endif /* CMM_MSG */
	vfprintf (stderr, format, ap);
	va_end (ap);

	fprintf (stderr, "\n");

	exit (2);
}

void error (const char *str) {

	fprintf (stderr, "\n");

	perror (str);

	exit (1);
}


/*  Set initial parameters according to how we was called   */

static void check_progname (const char *name) {
	const char *p;
	int l;

	p = strrchr (name, '/');
	if (p)  p++;
	else  p = name;

	l = strlen (p);
	if (l <= 0)  return;
	l--;

	if (p[l] == '6')  af = AF_INET6;
	else if (p[l] == '4')  af = AF_INET;

	if (!strncmp (p, "tcp", 3))
		ops = &tcp_ops;
	if (!strncmp (p, "tracert", 7))
		ops = &icmp_ops;

	return;
}


static int getaddr (const char *name, sockaddr_any *addr) {
	int ret;
	struct addrinfo hints, *ai, *res = NULL;
#ifdef CMM_MSG /* Yang Caiyong, 25Jul2012 */
	char err[1024] = {0};
#endif /* CMM_MSG */

	memset (&hints, 0, sizeof (hints));
	hints.ai_family = af;
#if 0 /* Yang Caiyong, 24Jul2012 */
	hints.ai_flags = AI_IDN;
#endif /* 0 */

	ret = getaddrinfo (name, NULL, &hints, &res);
	if (ret) {
#ifdef CMM_MSG /* Yang Caiyong, 25Jul2012 */
		sprintf (err, "%s: %s\n", name, gai_strerror (ret));
		send_result(TRACE_RESOLVE_FAILED, 0, "0.0.0.0", err);
		//printf("[ %s ] %d: err(%s)\n", __FUNCTION__, __LINE__, err);
#endif /* CMM_MSG */
		fprintf (stderr, "%s: %s\n", name, gai_strerror (ret));
		return -1;
	}

	for (ai = res; ai; ai = ai->ai_next) {
	    if (ai->ai_family == af)  break;
	    /*  when af not specified, choose DEF_AF if present   */
	    if (!af && ai->ai_family == DEF_AF)
		    break;
	}
	if (!ai)  ai = res;	/*  anything...  */

	if (ai->ai_addrlen > sizeof (*addr))
		return -1;	/*  paranoia   */
	memcpy (addr, ai->ai_addr, ai->ai_addrlen);

	freeaddrinfo (res);

	return 0;
}


static void make_fd_used (int fd) {
	int nfd;

	if (fcntl (fd, F_GETFL) != -1)
		return;

	if (errno != EBADF)
		error ("fcntl F_GETFL");

	nfd = open ("/dev/null", O_RDONLY);
	if (nfd < 0)  error ("open /dev/null");

	if (nfd != fd) {
	    dup2 (nfd, fd);
	    close (nfd);
	}

	return;
}


static char addr2str_buf[INET6_ADDRSTRLEN];

static const char *addr2str (const sockaddr_any *addr) {

	getnameinfo (&addr->sa, sizeof (*addr),
		addr2str_buf, sizeof (addr2str_buf), 0, 0, NI_NUMERICHOST);

	return addr2str_buf;
}


/*	IP  options  stuff	    */
static void init_ip_options (void) {
	sockaddr_any *gates;
	int i, max;

	if (!num_gateways)
		return;

	max = af == AF_INET ? MAX_GATEWAYS_4 : MAX_GATEWAYS_6;
	if (num_gateways > max)
	    ex_error ("Too many gateways specified. No more than %d", max);


	gates = alloca (num_gateways * sizeof (*gates));

	for (i = 0; i < num_gateways; i++) {

	    if (!gateways[i])  error ("strdup");

	    if (getaddr (gateways[i], &gates[i]) < 0)
		    ex_error ("");	/*  already reported   */
	    if (gates[i].sa.sa_family != af)
		    ex_error ("IP versions mismatch in gateway addresses");

	    free (gateways[i]);
	}

	free (gateways);
	gateways = NULL;


	if (af == AF_INET) {
	    struct in_addr *in;

	    rtbuf_len = 4 + (num_gateways + 1) * sizeof (*in);
	    rtbuf = malloc (rtbuf_len);
	    if (!rtbuf)  error ("malloc");

	    in = (struct in_addr *) &rtbuf[4];
	    for (i = 0; i < num_gateways; i++)
		    memcpy (&in[i], &gates[i].sin.sin_addr, sizeof (*in));
	    /*  final hop   */
	    memcpy (&in[i], &dst_addr.sin.sin_addr, sizeof (*in));
	    i++;

	    rtbuf[0] = IPOPT_NOP;
	    rtbuf[1] = IPOPT_LSRR;
	    rtbuf[2] = (i * sizeof (*in)) + 3;
	    rtbuf[3] = IPOPT_MINOFF;

	}
	else if (af == AF_INET6) {
	    struct in6_addr *in6;
	    struct ip6_rthdr *rth;

	    /*  IPV6_RTHDR_TYPE_0 length is 8   */
	    rtbuf_len = 8 + num_gateways * sizeof (*in6);
	    rtbuf = malloc (rtbuf_len);
	    if (!rtbuf)  error ("malloc");

	    rth = (struct ip6_rthdr *) rtbuf;
	    rth->ip6r_nxt = 0;
	    rth->ip6r_len = 2 * num_gateways;
	    rth->ip6r_type = IPV6_RTHDR_TYPE_0;
	    rth->ip6r_segleft = num_gateways;

	    *((u_int32_t *) (rth + 1)) = 0;

	    in6 = (struct in6_addr *) (rtbuf + 8);
	    for (i = 0; i < num_gateways; i++)
		    memcpy (&in6[i], &gates[i].sin6.sin6_addr, sizeof (*in6));
	}

	return;
}


/*	Command line stuff	    */

static int set_af (CLIF_option *optn, char *arg) {
	int vers = (int) optn->data;

	if (vers == 4)  af = AF_INET;
	else if (vers == 6)  af = AF_INET6;
	else
	    return -1;

	return 0;
}

static int add_gateway (CLIF_option *optn, char *arg) {

	if (num_gateways >= MAX_GATEWAYS_6) {	/*  127 > 8 ... :)   */
		fprintf (stderr, "Too many gateways specified.");
		return -1;
	}

	gateways = realloc (gateways, (num_gateways + 1) * sizeof (*gateways));
	if (!gateways)  error ("malloc");
	gateways[num_gateways++] = strdup (arg);

	return 0;
}

static int set_source (CLIF_option *optn, char *arg) {

	return  getaddr (arg, &src_addr);
}

	
static int set_ops (CLIF_option *optn, char *arg) {

	ops = (tr_ops *) optn->data;

	return 0;
}


static int set_host (CLIF_argument *argm, char *arg, int index) {

	if (getaddr (arg, &dst_addr) < 0)
		return -1;

	dst_name = arg;

	/*  i.e., guess it by the addr in cmdline...  */
	if (!af)  af = dst_addr.sa.sa_family;

	return 0;
}


static CLIF_option option_list[] = {
	{ "4", 0, 0, "Use IPv4", set_af, (void *) 4, 0, CLIF_EXTRA },
	{ "6", 0, 0, "Use IPv6", set_af, (void *) 6, 0, 0 },
	{ "d", "debug", 0, "Enable socket level debugging",
			CLIF_set_flag, &debug, 0, 0 },
	{ "F", "dont-fragment", 0, "Set DF (don't fragment bit) on",
			CLIF_set_flag, &dontfrag, 0, CLIF_ABBREV },
	{ "f", "first", "first_ttl", "Start from the %s hop (instead from 1)",
			CLIF_set_uint, &first_hop, 0, 0 },
	{ "g", "gateway", "gate", "Route packets throw the specified gateway "
			    "(maximum " _TEXT(MAX_GATEWAYS_4) " for IPv4 and "
			    _TEXT(MAX_GATEWAYS_6) " for IPv6)",
			add_gateway, 0, 0, CLIF_SEVERAL },
	{ "I", "icmp", 0, "Use ICMP ECHO for tracerouting",
			set_ops, &icmp_ops, 0, 0 },
	{ "T", "tcp", 0, "Use TCP SYN for tracerouting",
			set_ops, &tcp_ops, 0, 0 },
	{ "U", "udp", 0, "Use UDP datagram (default) for tracerouting",
			set_ops, &udp_ops, 0, CLIF_EXTRA },
	{ "i", "interface", "device", "Specify a network interface "
			    "to operate with",
			CLIF_set_string, &device, 0, 0 },
	{ "m", "max-hops", "max_ttl", "Set the max number of hops (max TTL "
			    "to be reached). Default is " _TEXT(DEF_HOPS) ,
			CLIF_set_uint, &max_hops, 0, 0 },
	{ "N", "sim-queries", "squeries", "Set the number of probes "
			    "to be tried simultaneously (default is "
			    _TEXT(DEF_SIM_PROBES) ")",
			CLIF_set_uint, &sim_probes, 0, 0 },
	{ "n", 0, 0, "Do not resolve IP addresses to their domain names",
			CLIF_set_flag, &noresolve, 0, 0 },
	{ "p", "port", "port", "Use destination port %s. "
			    "It is an initial value for the UDP destination "
			    "port (incremented by each probe, default is "
			    _TEXT(DEF_UDP_PORT) "), for the ICMP "
			    "seq number (incremented as well, default from 1), "
			    "and the constant destination port for TCP tries "
			    "(default is " _TEXT(DEF_TCP_PORT) ")",
			    CLIF_set_uint, &dst_port_seq, 0, 0 },
	{ "t", "tos", "tos", "Set the TOS (IPv4 type of service) or TC "
			    "(IPv6 traffic class) value for outgoing packets",
			    CLIF_set_uint, &tos, 0, 0 },
	{ "l", "flowlabel", "flow_label", "Use specified %s for IPv6 packets",
			    CLIF_set_uint, &flow_label, 0, 0 },
	{ "w", "wait", "waittime", "Set the number of seconds to wait for "
			    "response to a probe (default is "
			    _TEXT(DEF_WAIT_SECS) "). Non-integer (float point) "
			    "values allowed too",
			    CLIF_set_double, &wait_secs, 0, 0 },
	{ "q", "queries", "nqueries", "Set the number of probes per each hop. "
			    "Default is " _TEXT(DEF_NUM_PROBES),
			    CLIF_set_uint, &probes_per_hop, 0, 0 },
	{ "r", 0, 0, "Bypass the normal routing and send directly to a host "
			    "on an attached network",
			    CLIF_set_flag, &noroute, 0, 0 },
	{ "s", "source", "src_addr", "Use source %s for outgoing packets",
			    set_source, 0, 0, 0 },
	{ "z", "sendwait", "sendwait", "Minimal time interval between probes "
			    "(default " _TEXT(DEF_SEND_SECS) "). If the value "
			    "is more than 10, then it specifies a number "
			    "in milliseconds, else it is a number of seconds "
			    "(float point values allowed too)",
			    CLIF_set_double, &send_secs, 0, 0 },
	{ "A", "as-path-lookups", 0, "Perform AS path lookups in routing "
			    "registries and print results directly after "
			    "the corresponding addresses",
			    CLIF_set_flag, &as_lookups, 0, 0 },
	CLIF_VERSION_OPTION (version_string),
	CLIF_HELP_OPTION,
	CLIF_END_OPTION
};

static CLIF_argument arg_list[] = {
        { "host", "The host to traceroute to",
				set_host, 0, CLIF_STRICT },
	{ "packetlen", "Specify an alternate probe packet length "
			"(default is " _TEXT(DEF_PACKET_LEN) ")."
			" Useless for TCP SYN",
				CLIF_arg_uint, &packet_len, 0 },
	CLIF_END_ARGUMENT
};


static void do_it (void);

int main (int argc, char *argv[]) {

	setlocale (LC_ALL, "");
	setlocale (LC_NUMERIC, "C");	/*  avoid commas in msec printed  */

	check_progname (argv[0]);


	if (CLIF_parse (argc, argv, option_list, arg_list,
				CLIF_MAY_JOIN_ARG | CLIF_HELP_EMPTY) < 0
	)  exit (2);


	if (geteuid () != 0 && ops != &udp_ops)
	    ex_error ("The specified type of tracerouting "
			"is allowed for superuser only");


	if (first_hop > max_hops)
		ex_error ("first hop out of range");
	if (max_hops > MAX_HOPS)
		ex_error ("max hops cannot be more than " _TEXT(MAX_HOPS));
	if (!probes_per_hop || probes_per_hop > MAX_PROBES)
		ex_error ("no more than " _TEXT(MAX_PROBES) " probes per hop");
	if (!sim_probes || sim_probes > max_hops * probes_per_hop)
		ex_error ("sim hops out of range");
	if (wait_secs < 0)
		ex_error ("bad wait seconds `%g' specified", wait_secs);
	if (packet_len > MAX_PACKET_LEN)
		ex_error ("too big packetlen %d specified", packet_len);
	if (src_addr.sa.sa_family && src_addr.sa.sa_family != af)
		ex_error ("IP version mismatch in addresses specified");
	if (send_secs < 0)
		ex_error ("bad sendtime `%g' specified", send_secs);
	if (send_secs >= 10)	/*  it is milliseconds   */
		send_secs /= 1000;

	if (af == AF_INET6 && (tos || flow_label))
		dst_addr.sin6.sin6_flowinfo =
			((tos & 0xff) << 20) | (flow_label & 0x000fffff);
#ifdef CMM_MSG /* Yang Caiyong, 07Aug2012 */
	entryProbes = probes_per_hop;
#endif /* CMM_MSG */

	/*  make sure we don't std{in|,out,err} to open sockets  */
	make_fd_used (0);
	make_fd_used (1);
	make_fd_used (2);


	init_ip_options ();


	num_probes = max_hops * probes_per_hop;
	probes = calloc (num_probes, sizeof (*probes));
	if (!probes)  error ("calloc");

	if (ops->init (dst_name, &dst_addr, dst_port_seq, packet_len) < 0)
		ex_error ("trace method's init failed");


	do_it ();

	return 0;
}


/*	POLL  STUFF	    */

static struct pollfd *pfd = NULL;
static unsigned int num_polls = 0;

void add_poll (int fd, int events) {
	int i;

	for (i = 0; i < num_polls && pfd[i].fd > 0; i++) ;

	if (i == num_polls) {
	    pfd = realloc (pfd, ++num_polls * sizeof (*pfd));
	    if (!pfd)  error ("realloc");
	}

	pfd[i].fd = fd;
	pfd[i].events = events;
}

void del_poll (int fd) {
	int i;

	for (i = 0; i < num_polls && pfd[i].fd != fd; i++) ;

	if (i < num_polls)  pfd[i].fd = -1;    /*  or just zero it...  */
}

static int cleanup_polls (void) {
	int i;

	for (i = 0; i < num_polls && pfd[i].fd > 0; i++) ;

	if (i < num_polls) {	/*  a hole have found   */
	    int j;

	    for (j = i + 1; j < num_polls; j++) {
		if (pfd[j].fd > 0) {
		    pfd[i++] = pfd[j];
		    pfd[j].fd = -1;
		}
	    }
	}

	return i;
}

static void do_poll (double timeout) {
	int nfds, n, i;

	nfds = cleanup_polls ();

	if (!nfds)  return;

	n = poll (pfd, nfds, timeout * 1000);
	if (n < 0) {
	    if (errno == EINTR)  return;
	    error ("poll");
	}

	for (i = 0; n && i < num_polls; i++) {
	    if (pfd[i].revents) {
		ops->recv_probe (pfd[i].fd, pfd[i].revents, probes, num_probes);
		n--;
	    }
	}

	return;
}


/*	PRINT  STUFF	    */

static int equal_addr (const sockaddr_any *a, const sockaddr_any *b) {

	if (!a->sa.sa_family)
		return 0;

	if (a->sa.sa_family != b->sa.sa_family)
		return 0;

	if (a->sa.sa_family == AF_INET6)
	    return  !memcmp (&a->sin6.sin6_addr, &b->sin6.sin6_addr,
						sizeof (a->sin6.sin6_addr));
	else
	    return  !memcmp (&a->sin.sin_addr, &b->sin.sin_addr,
						sizeof (a->sin.sin_addr));
	return 0;	/*  not reached   */
}

#ifdef CMM_MSG /* Yang Caiyong, 20Jul2012 */
void send_result(int errCode, int resTime, char *ip, char *result)
{
	CMSG_FD msgFd;
	CMSG_BUFF msgBuff;
	TRACERT_CFG_MSG *pTraceRtCfgMsg = NULL;
	memset(&msgFd, 0, sizeof(CMSG_FD));
	memset(&msgBuff, 0, sizeof(CMSG_BUFF));

	pTraceRtCfgMsg = (TRACERT_CFG_MSG *)(msgBuff.content);
	msgBuff.type = CMSG_TRACERT_CFG_MSG;
	//printf("[ %s ] %d: type(%d)\n", __FUNCTION__, __LINE__, msgBuff.type);

	pTraceRtCfgMsg->responseTime= responseTime;
	responseTime = 0;
	if (ip[0])
	{
		strcpy(pTraceRtCfgMsg->ipAddr, ip);
	}
	if (result[0])
	{
		strncpy(pTraceRtCfgMsg->result, result, sizeof(pTraceRtCfgMsg->result));
	}

	switch (errCode)
	{
	case TRACE_HEAD:
		pTraceRtCfgMsg->succuss = TRACE_HEAD;
		strcpy(pTraceRtCfgMsg->diagnosticsState, "None");
		break;
	case TRACE_SUCC:
		pTraceRtCfgMsg->succuss = TRACE_SUCC;
		strcpy(pTraceRtCfgMsg->diagnosticsState, "None");
		break;
	case TRACE_RESOLVE_FAILED:
		/* time out */
		pTraceRtCfgMsg->succuss = TRACE_RESOLVE_FAILED;
		//sprintf(pTraceRtCfgMsg->result, ": Name or service not known.");
		strcpy(pTraceRtCfgMsg->diagnosticsState, "Error_CannotResolveHostName");
		break;
	case TRACE_HOP_EXCEED:
		pTraceRtCfgMsg->succuss = TRACE_HOP_EXCEED;
		strcpy(pTraceRtCfgMsg->diagnosticsState, "Error_MaxHopCountExceeded");
		break;
	case TRACE_FAILED:
		pTraceRtCfgMsg->succuss = TRACE_FAILED;
		strcpy(pTraceRtCfgMsg->diagnosticsState, "Error_CannotResolveHostName");
		break;
	case TRACE_COMPLETE:
		pTraceRtCfgMsg->succuss = TRACE_COMPLETE;
		strcpy(pTraceRtCfgMsg->diagnosticsState, "Complete");
		break;
	default:
		return;
	}
	traceResult = TRACE_HEAD;
	msg_init(&msgFd);
	msg_connSrv(CMSG_ID_COS, &msgFd);
	msg_send(&msgFd, &msgBuff);
	msg_cleanup(&msgFd);
}
#endif /* CMM_MSG */

static void print_header (void) {

#ifdef CMM_MSG /* Yang Caiyong, 24Jul2012 */
	char headerStr[1024] = {0};
#endif /* CMM_MSG */
	/*  Note, without ending new-line!  */
	printf ("traceroute to %s (%s), %u hops max, %u byte packets",
			dst_name, addr2str (&dst_addr), max_hops, packet_len);
#ifdef CMM_MSG /* Yang Caiyong, 24Jul2012 */
	sprintf (headerStr, "traceroute to %s (%s), %u hops max, %u byte packets",
			dst_name, addr2str (&dst_addr), max_hops, packet_len);
	send_result(TRACE_HEAD, 0, addr2str (&dst_addr), headerStr);
#endif /* CMM_MSG */
	fflush (stdout);
}

#ifdef CMM_MSG /* Yang Caiyong, 24Jul2012 */
static void print_addr (sockaddr_any *res, char *result) {
	const char *str;

	if (!res->sa.sa_family) {
#ifdef CMM_MSG /* Yang Caiyong, 14Aug2012 */
		sprintf(result + strlen(result), " *");
		traceResult = TRACE_FAILED;
		++entryCompelete;
#endif /* CMM_MSG */
		printf (" *");
		return;
	}

	str = addr2str (res);


	if (noresolve)
	{
		sprintf(result + strlen(result), " %s", str);
		printf (" %s", str);
	}
	else {
	    char buf[1024];

	    buf[0] = '\0';
	    getnameinfo (&res->sa, sizeof (*res), buf, sizeof (buf),
							    0, 0, NI_IDN);
	    /*  foo on errors.  */
		sprintf(result + strlen(result), " %s (%s)", buf, str);
	    printf (" %s (%s)", buf, str);
	}

	if (as_lookups)
	{
		sprintf(result + strlen(result), " [%s]", get_as_path (str));
		printf (" [%s]", get_as_path (str));
	}
}
#else
static void print_addr (sockaddr_any *res) {
	const char *str;

	if (!res->sa.sa_family) {
		printf (" *");
		return;
	}

	str = addr2str (res);


	if (noresolve)
		printf (" %s", str);
	else {
	    char buf[1024];

	    buf[0] = '\0';
	    getnameinfo (&res->sa, sizeof (*res), buf, sizeof (buf),
							    0, 0, NI_IDN);
	    /*  foo on errors.  */

	    printf (" %s (%s)", buf, str);
	}

	if (as_lookups)
		printf (" [%s]", get_as_path (str));
}
#endif /* CMM_MSG */

#ifdef CMM_MSG /* Yang Caiyong, 25Jul2012 */
static void print_probe (probe *pb, char *result) {
#else
static void print_probe (probe *pb) {
#endif /* CMM_MSG */
	unsigned int idx, np;

	idx = (pb - probes);
	np = idx % probes_per_hop;

	if (np == 0) {
	    int ttl;

	    ttl = idx / probes_per_hop + 1;
		/* Previous message haven't send yet. send first. */
#ifdef CMM_MSG /* Yang Caiyong, 13Aug2012 */
		if (result[0])
		{
			char time[5] = {0};
			int i = 0, j = 0;
			/* found the dot of last time. */
			for (i = strlen(result) - 1; result[i] != '.'; --i)
				;
			/* found the space before the last time. */
			for (j = i; result[j] != ' '; --j)
				;
			strncpy(time, result + j + 1 , i - j - 1);
			//printf("[ %s ] %d: time(%s) traceResult(%d) \nresult(%s)\n", __FUNCTION__, __LINE__, 
				//time, traceResult, result);
			send_result(traceResult, (double)atoi(time), addr2str (&dst_addr), result);
			memset(result, '\0', sizeof(result));
		}
#endif /* CMM_MSG */

	    printf ("\n%2u ", ttl);
#ifdef CMM_MSG /* Yang Caiyong, 24Jul2012 */
		sprintf(result + strlen(result), "%2u ", ttl);
		print_addr (&pb->res, result);
#else
		print_addr (&pb->res);
#endif /* CMM_MSG */	    
	}
	else {	/*  print if differs with previous   */
	    probe *p;

	    /*  skip expired   */
	    for (p = pb - 1; np && !p->res.sa.sa_family; p--, np--) ;

	    if (!np || !equal_addr (&p->res, &pb->res))
	    {
#ifdef CMM_MSG /* Yang Caiyong, 24Jul2012 */
			print_addr (&pb->res, result);
#else
			print_addr (&pb->res);
#endif /* CMM_MSG */
	    }
	}

	if (pb->recv_time) {
	    double diff = pb->recv_time - pb->send_time;

#ifdef CMM_MSG /* Yang Caiyong, 24Jul2012 */
		sprintf(result + strlen(result), "  %.3f ms", diff * 1000);
		++entryCompelete;
		responseTime = diff * 1000;
#endif /* CMM_MSG */
		printf ("  %.3f ms", diff * 1000);
	}

	if (pb->err_str[0])
	{
#ifdef CMM_MSG /* Yang Caiyong, 24Jul2012 */
		sprintf(result + strlen(result), " %s", pb->err_str);
		entryCompelete = entryProbes;
		traceResult = TRACE_FAILED;
#endif /* CMM_MSG */
		printf (" %s", pb->err_str);
	}

	fflush (stdout);

	return;
}

static void print_end (void) {

	printf ("\n");
}


/*	Check  expiration  stuff	*/

static void check_expired (probe *pb) {
	int idx = (pb - probes);
	probe *p, *endp = probes + num_probes;
	probe *fp = NULL, *pfp = NULL;

	if (!pb->done)	    /*  an ops method still not release it  */
	    return;


	/*  check all the previous in the same hop   */
	for (p = &probes[idx - (idx % probes_per_hop)]; p < pb; p++) {

	    if (!p->done ||     /*  too early to decide something  */
		!p->final       /*  already ttl-exceeded in the same hop  */
	    )  return;

	    pfp = p;	/*  some of the previous probes is final   */
	}

	/*  check forward all the sent probes   */
	for (p = pb + 1; p < endp && p->send_time; p++) {

	    if (p->done) {	/*  some next probe already done...  */
		if (!p->final)	/*  ...was ttl-exceeded. OK, we are expired.  */
		    return;
		else {
		    fp = p;
		    break;
		}
	    }
	}

	if (!fp)    /*  no any final probe found. Assume expired.   */
	    return;


	/*  Well. There is a situation "*(this) * * * * ... * * final"
	   We cannot guarantee that "final" is in its right place.
	   We've sent "sim_probes" simultaneously, and the final hop
	   can drop some of them and answer only for latest ones.
	   If we can detect/assume that it so, then just put "final"
	   to the (pseudo-expired) "this" place.
	*/

	if (pfp ||
	    (idx % probes_per_hop) + (fp - pb) < probes_per_hop
	) {
	    /*  Either some previous (pfp) or some next probe
		in this hop is final. It means that the whole hop is final.
		Do the replace (it also causes further "final"s to be shifted
		here too).
	    */
	    goto  replace_by_final;
	}


	/*  If the final probe is an icmp_unreachable report
	    (either in a case of some error, like "!H", or just port_unreach),
	    it could follow the "time-exceed" report from the *same* hop.
	*/
	for (p = pb - 1; p >= probes; p--) {
	    if (equal_addr (&p->res, &fp->res)) {
		/*  ...Yes. Put "final" to the "this" place.  */
		goto  replace_by_final;
	    }
	}


	if (fp->recv_ttl) {
	    /*  Consider the ttl value of the report packet and guess where
		the "final" should be. If it seems that it should be
		in the same hop as "this", then do replace.
	    */
	    int back_hops, ttl;

	    /*  We assume that the reporting one has an initial ttl value
		of either 64, or 128, or 255. It is most widely used
		in the modern routers and computers.
		The idea comes from tracepath(1) routine.
	    */
#define ttl2hops(X)	(((X) <= 64 ? 65 : ((X) <= 128 ? 129 : 256)) - (X))

	    back_hops = ttl2hops (fp->recv_ttl);

	    /*  It is possible that the back path differs from the forward
		and therefore has different number of hops. To minimize
		such an influence, get the nearest previous time-exceeded
		probe and compare with it.
	    */
	    for (p = pb - 1; p >= probes; p--) {
		if (p->done && !p->final && p->recv_ttl) {
		    int hops = ttl2hops (p->recv_ttl);

		    if (hops < back_hops) {
			ttl = (p - probes) / probes_per_hop + 1;
			back_hops = (back_hops - hops) + ttl;
			break;
		    }
		}
	    }

	    ttl = idx / probes_per_hop + 1;
	    if (back_hops == ttl)
		/*  Yes! It seems that "final" should be at "this" place   */
		goto  replace_by_final;
	    else if (back_hops < ttl)
		/*  Hmmm... Assume better to replace here too...  */
		goto  replace_by_final;

	}


	/*  No idea what to do. Assume expired.  */

	return;


replace_by_final:

	*pb = *fp;

	memset (fp, 0, sizeof (*fp));
	/*  block extra re-send  */
	fp->send_time = 1.;

	return;
}


static void do_it (void) {
	int start = first_hop * probes_per_hop;
	int end = num_probes;
	double last_send = 0;
#ifdef CMM_MSG /* Yang Caiyong, 24Jul2012 */
	char result[1024] = {0};
	double diff = 0;
#endif /* CMM_MSG */

	print_header ();


	while (start < end) 
	{
	    int n, num = 0;
	    double max_time = 0;
	    double now_time = get_time ();


	    for (n = start; n < end; n++) 
		{
			probe *pb = &probes[n];

			if (!pb->done &&
			    pb->send_time &&
			    now_time - pb->send_time >= wait_secs) 
			{
			    ops->expire_probe (pb);
			    check_expired (pb);
			}


			if (pb->done) 
			{
			    if (n == start) 
				{	/*  can print it now   */
#ifdef CMM_MSG /* Yang Caiyong, 25Jul2012 */
					print_probe(pb, result);
					diff = pb->recv_time - pb->send_time;
#else
					print_probe (pb);
#endif /* CMM_MSG */
					start++;
				}
			    if (pb->final)
					end = (n / probes_per_hop + 1) * probes_per_hop;

			    continue;
			}

			if (!pb->send_time) 
			{
			    int ttl;

			    if (send_secs && (now_time - last_send) < send_secs) 
				{
					max_time = (last_send + send_secs) - wait_secs;
					break;
			    }

			    ttl = n / probes_per_hop + 1;

			    ops->send_probe (pb, ttl);

			    last_send = pb->send_time;
			}

			if (pb->send_time > max_time)
				max_time = pb->send_time;

			num++;
			if (num >= sim_probes)  break;
		}

#ifdef CMM_MSG /* Yang Caiyong, 25Jul2012 */
		/* last trace. */
		if (strstr(result, addr2str (&dst_addr)))
		{
			traceResult = TRACE_COMPLETE;
		}
		//printf("\n\n+++++[ %s ] %d: dst_addr(%s)result{%s} traceResult(%d) entryCompelete(%d) entryProbes(%d)+++++++\n\n", __FUNCTION__, __LINE__, 
			//addr2str(&dst_addr), result, traceResult, entryCompelete, entryProbes);
		if (traceResult != TRACE_HEAD)
		{
			if (entryProbes == entryCompelete)
			{
				if (result[0])
					send_result(traceResult, diff, addr2str (&dst_addr), result);
				//printf("\n[ %s ] %d: result{%s} traceResult(%d)\n", __FUNCTION__, __LINE__, result, traceResult);
				entryCompelete = 0;
				memset(result, '\0', sizeof(result));
			}
			else if (traceResult != TRACE_SUCC)
			{
				entryCompelete = 0;
				if (result[0])
					send_result(traceResult, diff, "0.0.0.0", result);
				memset(result, '\0', sizeof(result));
			}
		}
#endif /* CMM_MGS */

	    if (max_time) 
		{
			double timeout = (max_time + wait_secs) - now_time;

			if (timeout < 0)  timeout = 0;

			do_poll (timeout);
	    }

	}


	print_end ();

	return;
}


void tune_socket (int sk) {
	int i = 0;

	if (debug) {
	    i = 1;
	    if (setsockopt (sk, SOL_SOCKET, SO_DEBUG, &i, sizeof (i)) < 0)
		    error ("setsockopt SO_DEBUG");
	}


	if (rtbuf && rtbuf_len) {
	    if (af == AF_INET) {
		if (setsockopt (sk, IPPROTO_IP, IP_OPTIONS,
						rtbuf, rtbuf_len) < 0
		)  error ("setsockopt IP_OPTIONS");
	    }
	    else if (af == AF_INET6) {
		if (setsockopt (sk, IPPROTO_IPV6, IPV6_RTHDR,
						rtbuf, rtbuf_len) < 0
		)  error ("setsockopt IPV6_RTHDR");
	    }
	}


	if (device) {
	    if (setsockopt (sk, SOL_SOCKET, SO_BINDTODEVICE,
					device, strlen (device) + 1) < 0
	    )  error ("setsockopt SO_BINDTODEVICE");
	}

	if (src_addr.sa.sa_family) {
	    if (bind (sk, &src_addr.sa, sizeof (src_addr)) < 0)
		    error ("bind");
	}


	if (af == AF_INET) {

	    i = dontfrag ? IP_PMTUDISC_DO : IP_PMTUDISC_DONT;
	    if (setsockopt (sk, SOL_IP, IP_MTU_DISCOVER, &i, sizeof(i)) < 0)
		    error ("setsockopt IP_MTU_DISCOVER");

	    if (tos) {
		i = tos;
		if (setsockopt (sk, SOL_IP, IP_TOS, &i, sizeof (i)) < 0)
			error ("setsockopt IP_TOS");
	    }

	}
	else if (af == AF_INET6) {

	    i = dontfrag ? IPV6_PMTUDISC_DO : IPV6_PMTUDISC_DONT;
	    if (setsockopt (sk, SOL_IPV6, IPV6_MTU_DISCOVER, &i, sizeof(i)) < 0)
		    error ("setsockopt IPV6_MTU_DISCOVER");

	    if (flow_label) {
		struct in6_flowlabel_req flr;

		memset (&flr, 0, sizeof (flr));
		flr.flr_label = htonl (flow_label & 0x000fffff);
                flr.flr_action = IPV6_FL_A_GET;
                flr.flr_flags = IPV6_FL_F_CREATE;
                flr.flr_share = IPV6_FL_S_EXCL;
		memcpy (&flr.flr_dst, &dst_addr.sin6.sin6_addr,
						    sizeof (flr.flr_dst));

		if (setsockopt (sk, IPPROTO_IPV6, IPV6_FLOWLABEL_MGR,
						    &flr, sizeof (flr)) < 0
		)  error ("setsockopt IPV6_FLOWLABEL_MGR");
	    }

	    if (tos || flow_label) {
		i = 1;
		if (setsockopt (sk, IPPROTO_IPV6, IPV6_FLOWINFO_SEND,
							&i, sizeof (i)) < 0
		)  error ("setsockopt IPV6_FLOWINFO_SEND");
	    }
	}
  

	if (noroute) {
	    i = noroute;
	    if (setsockopt (sk, SOL_SOCKET, SO_DONTROUTE, &i, sizeof (i)) < 0)
		    error ("setsockopt SO_DONTROUTE");
	}


	use_timestamp (sk);

	use_recv_ttl (sk);

	fcntl (sk, F_SETFL, O_NONBLOCK);

	return;
}


void parse_icmp_res (probe *pb, int type, int code) {
	char *str = "";
	char buf[16];

	if (af == AF_INET) {
#ifdef CMM_MSG /* Yang Caiyong, 25Jul2012 */
		traceResult = TRACE_SUCC;
#endif /* CMM_MSG */

	    if (type == ICMP_TIME_EXCEEDED) {
			if (code == ICMP_EXC_TTL){
#if 0 /* Yang Caiyong, 25Jul2012 */
				traceResult = TRACE_HOP_EXCEED;
#endif /* CMM_MSG */
				return;
			}
	    }
	    else if (type == ICMP_DEST_UNREACH) {
#ifdef CMM_MSG /* Yang Caiyong, 07Aug2012 */
			//printf("[ %s ] %d: type(%d)\n", __FUNCTION__, __LINE__, type);
			traceResult = TRACE_FAILED;
#endif /* CMM_MSG */

		switch (code) {
		    case ICMP_UNREACH_NET:
		    case ICMP_UNREACH_NET_UNKNOWN:
		    case ICMP_UNREACH_ISOLATED:
		    case ICMP_UNREACH_TOSNET:
			    str = "!N";
			    break;

		    case ICMP_UNREACH_HOST:
		    case ICMP_UNREACH_HOST_UNKNOWN:
		    case ICMP_UNREACH_TOSHOST:
			    str = "!H";
			    break;

		    case ICMP_UNREACH_NET_PROHIB:
		    case ICMP_UNREACH_HOST_PROHIB:
		    case ICMP_UNREACH_FILTER_PROHIB:
			    str = "!X";
#ifdef CMM_MSG /* Yang Caiyong, 08Aug2012 */
				traceResult = TRACE_COMPLETE;
#endif /* CMM_MSG */
			    break;

		    case ICMP_UNREACH_PORT:
			    /*  dest host is reached   */
#ifdef CMM_MSG /* Yang Caiyong, 07Aug2012 */
				traceResult = TRACE_SUCC;
#endif /* CMM_MSG */
			    str = NULL;
			    break;

		    case ICMP_UNREACH_PROTOCOL:
			    str = "!P";
			    break;

		    case ICMP_UNREACH_NEEDFRAG:
			    str = "!F";
			    break;

		    case ICMP_UNREACH_SRCFAIL:
			    str = "!S";
			    break;

		    case ICMP_UNREACH_HOST_PRECEDENCE:
			    str = "!V";
			    break;

		    case ICMP_UNREACH_PRECEDENCE_CUTOFF:
			    str = "!C";
			    break;

		    default:
			    snprintf (buf, sizeof (buf), "!<%u>", code);
			    str = buf;
			    break;
		}
	    }

	}
	else if (af == AF_INET6) {

	    if (type == ICMP6_TIME_EXCEEDED) {
		if (code == ICMP6_TIME_EXCEED_TRANSIT)
			return;
	    }
	    else if (type == ICMP6_DST_UNREACH) {

		switch (code) {

		    case ICMP6_DST_UNREACH_NOROUTE:
			    str = "!N";
			    break;

		    case ICMP6_DST_UNREACH_BEYONDSCOPE:
		    case ICMP6_DST_UNREACH_ADDR:
			    str = "!H";
			    break;

		    case ICMP6_DST_UNREACH_ADMIN:
			    str = "!X";
			    break;

		    case ICMP6_DST_UNREACH_NOPORT:
			    /*  dest host is reached   */
			    str = NULL;
			    break;

		    default:
			    snprintf (buf, sizeof (buf), "!<%u>", code);
			    str = buf;
			    break;
		}
	    }
	}

	if (str && !*str) {
	    snprintf (buf, sizeof (buf), "!<%u-%u>", type, code);
	    str = buf;
	}

	if (str) {
	    strncpy (pb->err_str, str, sizeof (pb->err_str));
	    pb->err_str[sizeof (pb->err_str) - 1] = '\0';
	}

	pb->final = 1;

	return;
}


void use_timestamp (int sk) {
	int n = 1;

	setsockopt (sk, SOL_SOCKET, SO_TIMESTAMP, &n, sizeof (n));
	/*  foo on errors...  */
}

double get_timestamp (struct msghdr *msg) {
	struct cmsghdr *cm;
	double timestamp = 0;

	for (cm = CMSG_FIRSTHDR (msg); cm; cm = CMSG_NXTHDR (msg, cm)) {

	    if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SO_TIMESTAMP) {
		struct timeval *tv = (struct timeval *)  CMSG_DATA (cm);

		timestamp = tv->tv_sec + tv->tv_usec / 1000000.;
	    }
	}

	if (!timestamp)
		timestamp = get_time ();

	return timestamp;
}


void use_recv_ttl (int sk) {
	int n = 1;

	if (af == AF_INET)
		setsockopt (sk, SOL_IP, IP_RECVTTL, &n, sizeof (n));
	else if (af == AF_INET6)
		setsockopt (sk, SOL_IPV6, IPV6_RECVHOPLIMIT, &n, sizeof (n));

	/*  foo on errors   */
	return;
}

int get_recv_ttl (struct msghdr *msg) {
	struct cmsghdr *cm;
	int ttl = 0;

	for (cm = CMSG_FIRSTHDR (msg); cm; cm = CMSG_NXTHDR (msg, cm)) {

	    if ((cm->cmsg_level == SOL_IP && cm->cmsg_type == IP_TTL) ||
		(cm->cmsg_level == SOL_IPV6 && cm->cmsg_type == IPV6_HOPLIMIT)
	    )  ttl = *((int *) CMSG_DATA (cm));
	}

	return ttl;
}
