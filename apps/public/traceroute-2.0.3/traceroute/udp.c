/*
    Copyright (c)  2006		    Dmitry K. Butskoy
				    <buc@citadel.stu.neva.ru>
    License:  GPL		

    See COPYING for the status of this software.
*/

#include <stdlib.h>
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
#include <errno.h>
#include <linux/types.h>
#include <linux/errqueue.h>

#include "traceroute.h"


static sockaddr_any dest_addr = {{ 0, }, };
static unsigned short dest_port = DEF_UDP_PORT;

static char *data;
static size_t data_len = 0;


static int udp_init (const char *host, const sockaddr_any *dest,
				unsigned int port_seq, size_t packet_len) {
	int i;

	dest_addr = *dest;
	dest_addr.sin.sin_port = 0;

	if (port_seq)  dest_port = port_seq;

	data_len = packet_len;
	data = malloc (data_len);
	if (!data)  error ("malloc");

        for (i = 0; i < data_len; i++)
                data[i] = 0x40 + (i & 0x3f);
 
	return 0;
}


static void udp_send_probe (probe *pb, int ttl) {
	int sk, val = 0;
	int af = dest_addr.sa.sa_family;
#ifdef CMM_MSG /* Yang Caiyong, 25Jul2012 */
	char result[1024] = {0};
#endif /* CMM_MSG */


	sk = socket (af, SOCK_DGRAM, 0);
	if (sk < 0)  error ("socket");

	tune_socket (sk);	/*  common stuff   */

	if (af == AF_INET) {

	    val = ttl;
	    if (setsockopt (sk, SOL_IP, IP_TTL, &val, sizeof (val)) < 0)
		    error ("setsockopt IP_TTL");

	    val = 1;
	    if (setsockopt (sk, SOL_IP, IP_RECVERR, &val, sizeof (val)) < 0)
		    error ("setsockopt IP_RECVERR");

	}
	else if (af == AF_INET6) {

	    val = ttl;
	    if (setsockopt (sk, SOL_IPV6, IPV6_UNICAST_HOPS,
						&val, sizeof (val)) < 0
	    )  error ("setsockopt IPV6_UNICAST_HOPS");

	    val = 1;
	    if (setsockopt (sk, SOL_IPV6, IPV6_RECVERR, &val, sizeof (val)) < 0)
		    error ("setsockopt IPV6_RECVERR");
	}


	pb->send_time = get_time ();

	dest_addr.sin.sin_port = htons (dest_port);	/* both ipv4 and ipv6 */
	dest_port++;

	if (connect (sk, &dest_addr.sa, sizeof (dest_addr)) < 0)
	{
#ifdef CMM_MSG /* Yang Caiyong, 07Aug2012 */
		sprintf(result, "connect: %s", strerror(errno));
		send_result(TRACE_FAILED, 0, "0.0.0.0", result);
		traceResult = TRACE_FAILED;
#endif /* CMM_MSG */
		error ("connect");
	}

	if (send (sk, data, data_len, 0) < 0)
		error ("send");


	pb->sk = sk;

	add_poll (sk, POLLERR);

	return;
}


static void udp_recv_probe (int sk, int revents, probe *probes,
						unsigned int num_probes) {
	struct msghdr msg;
	sockaddr_any from;
	char control[1024];
	struct cmsghdr *cm;
	int i;
	probe *pb;


	if (!(revents | POLLERR))
		return;


	memset (&msg, 0, sizeof (msg));

	msg.msg_name = &from;
	msg.msg_namelen = sizeof (from);
	msg.msg_control = control;
	msg.msg_controllen = sizeof (control);

	if (recvmsg (sk, &msg, MSG_ERRQUEUE) < 0)
		return;


	for (i = 0; i < num_probes && probes[i].sk != sk; i++) ;
	if (i >= num_probes)  return;
	pb = &probes[i];


	for (cm = CMSG_FIRSTHDR (&msg); cm; cm = CMSG_NXTHDR (&msg, cm)) {

	    if ((cm->cmsg_level == SOL_IP && cm->cmsg_type == IP_RECVERR) ||
		(cm->cmsg_level == SOL_IPV6 && cm->cmsg_type == IPV6_RECVERR)
	    ) {
		struct sock_extended_err *ee;

		ee = (struct sock_extended_err *) CMSG_DATA (cm);
		memcpy (&pb->res, SO_EE_OFFENDER (ee), sizeof (pb->res));

		if (ee->ee_origin == SO_EE_ORIGIN_ICMP ||
		    ee->ee_origin == SO_EE_ORIGIN_ICMP6
		)  parse_icmp_res (pb, ee->ee_type, ee->ee_code);
	    }
	}

	pb->recv_time = get_timestamp (&msg);

	pb->recv_ttl = get_recv_ttl (&msg);


	del_poll (sk);

	close (sk);
	pb->sk = -1;

	pb->done = 1;
}


static void udp_expire_probe (probe *pb) {

	del_poll (pb->sk);

	close (pb->sk);
	pb->sk = -1;

	pb->done = 1;
}


tr_ops udp_ops = {
	.init = udp_init,
	.send_probe = udp_send_probe,
	.recv_probe = udp_recv_probe,
	.expire_probe = udp_expire_probe,
};

