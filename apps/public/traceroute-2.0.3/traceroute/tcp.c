/*
    Copyright (c)  2006		    Dmitry K. Butskoy
				    <buc@citadel.stu.neva.ru>
    License:  GPL		

    See COPYING for the status of this software.
*/

#include <stdlib.h>
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
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <errno.h>
#include <linux/types.h>
#include <linux/errqueue.h>

#include "traceroute.h"


static sockaddr_any dest_addr = {{ 0, }, };

static int icmp_sk = -1;


static int tcp_init (const char *host, const sockaddr_any *dest,
				unsigned int port_seq, size_t packet_len) {
	int af = dest->sa.sa_family;

	dest_addr = *dest;
	dest_addr.sin.sin_port = htons (DEF_TCP_PORT);

	if (port_seq)
	    dest_addr.sin.sin_port = htons (port_seq);


	/*  Currently an ICMP socket is the only way
	  to obtain the needed info...
	*/
	icmp_sk = socket (af, SOCK_RAW, (af == AF_INET) ? IPPROTO_ICMP
							: IPPROTO_ICMPV6);
	if (icmp_sk < 0)
		error ("socket");

	/*  icmp_sk not need full tune_socket() here, just a receiving one  */
	use_timestamp (icmp_sk);
	use_recv_ttl (icmp_sk);

	add_poll (icmp_sk, POLLIN);

	return 0;
}


static void tcp_send_probe (probe *pb, int ttl) {
	int sk;
	int af = dest_addr.sa.sa_family;
	sockaddr_any addr;
	size_t length = sizeof (addr);


	sk = socket (af, SOCK_STREAM, 0);
	if (sk < 0)  error ("socket");

	tune_socket (sk);	/*  common stuff   */

	if (af == AF_INET) {
	    if (setsockopt (sk, SOL_IP, IP_TTL, &ttl, sizeof (ttl)) < 0)
		    error ("setsockopt IP_TTL");
	}
	else if (af == AF_INET6) {
	    if (setsockopt (sk, SOL_IPV6, IPV6_UNICAST_HOPS,
						&ttl, sizeof (ttl)) < 0
	    )  error ("setsockopt IPV6_UNICAST_HOPS");
	}


	pb->send_time = get_time ();

	if (connect (sk, &dest_addr.sa, sizeof (dest_addr)) < 0) {
	    if (errno != EINPROGRESS)
		    error ("connect");
	}


	if (getsockname (sk, &addr.sa, &length) < 0)
		error ("getsockname");

	pb->seq = ntohs (addr.sin.sin_port);	/*  both ipv4/ipv6  */

	pb->sk = sk;

	add_poll (sk, POLLERR | POLLHUP | POLLOUT);

	return;
}


static void tcp_recv_probe (int sk, int revents, probe *probes,
						unsigned int num_probes) {
	int af = dest_addr.sa.sa_family;
	struct msghdr msg;
	sockaddr_any from;
	struct iovec iov;
	int i, n, type, code;
	probe *pb;
	u_int16_t recv_seq;
	char buf[1024];
	char control[1024];


	if (sk != icmp_sk) {	/*  a tcp socket   */

	    for (i = 0; i < num_probes && probes[i].sk != sk; i++) ;
	    if (i >= num_probes) {
		del_poll (sk);
		return;
	    }
	    pb = &probes[i];


	    /*  do connect() again and check errno, regardless of revents  */
	    if (connect (sk, &dest_addr.sa, sizeof (dest_addr)) < 0) {
		if (errno != EISCONN && errno != ECONNREFUSED)
			return;	/*  ICMP say more   */
	    }

	    /*  we have reached the dest host (either connected or refused)  */

	    memcpy (&pb->res, &dest_addr, sizeof (pb->res));

	    pb->final = 1;

	    pb->recv_time = get_time ();
	    del_poll (sk);

	    close (sk);
	    pb->sk = -1;
	    pb->seq = 0;

	    pb->done = 1;

	    return;
	}


	/*  ICMP stuff   */

	if (!(revents | POLLIN))
		return;

	memset (&msg, 0, sizeof (msg));
	msg.msg_name = &from;
	msg.msg_namelen = sizeof (from);
	msg.msg_control = control;
	msg.msg_controllen = sizeof (control);
	iov.iov_base = buf;
	iov.iov_len = sizeof (buf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	n = recvmsg (icmp_sk, &msg, 0);
	if (n < sizeof (struct icmphdr))	/*  error or too short   */
		return;


	if (af == AF_INET) {
	    struct iphdr *ip = (struct iphdr *) buf;
	    int hlen = ip->ihl << 2;
	    struct icmp *icmp;

	    n -= hlen + sizeof (struct icmphdr);
	    if (n < 0)  return;

	    icmp = (struct icmp *) (buf + hlen);
	    type = icmp->icmp_type;
	    code = icmp->icmp_code;

	    if (type == ICMP_TIME_EXCEEDED ||
		type == ICMP_DEST_UNREACH
	    ) {
		struct tcphdr *tcp;

		if (n < sizeof (struct iphdr) + 8)  /* `8' - rfc1122: 3.2.2  */
			return;

		ip = (struct iphdr *) (((char *)icmp) + sizeof(struct icmphdr));
		hlen = ip->ihl << 2;

		if (n < hlen + 8)
			return;
		if (ip->protocol != IPPROTO_TCP)
			return;

		tcp = (struct tcphdr *) (((char *) ip) + hlen);
		recv_seq = ntohs (tcp->source);

	    } else
		return;
	}
	else {	    /*  AF_INET6   */
	    struct icmp6_hdr *icmp6 = (struct icmp6_hdr *) buf;

	    type = icmp6->icmp6_type;
	    code = icmp6->icmp6_code;

	    if (type == ICMP6_TIME_EXCEEDED ||
		type == ICMP6_DST_UNREACH
	    ) {
		struct ip6_hdr *ip6;
		struct tcphdr *tcp;

		if (n < sizeof (struct icmp6_hdr) + sizeof (struct ip6_hdr) + 8)
			return;

		ip6 = (struct ip6_hdr *) (icmp6 + 1);
		if (ip6->ip6_nxt != IPPROTO_TCP)
			return;

		tcp = (struct tcphdr *) (ip6 + 1);
		recv_seq = ntohs (tcp->source);

	    } else
		return;
	}


	for (i = 0; i < num_probes && probes[i].seq != recv_seq; i++) ;
	if (i >= num_probes)  return;
	pb = &probes[i];


	memcpy (&pb->res, &from, sizeof (pb->res));

	parse_icmp_res (pb, type, code);

	pb->recv_time = get_timestamp (&msg);

	pb->recv_ttl = get_recv_ttl (&msg);


	pb->seq = 0;

	del_poll (pb->sk);
	close (pb->sk);
	pb->sk = -1;

	pb->done = 1;
}


static void tcp_expire_probe (probe *pb) {

	del_poll (pb->sk);

	close (pb->sk);
	pb->sk = -1;
	pb->seq = 0;

	pb->done = 1;
}


tr_ops tcp_ops = {
	.init = tcp_init,
	.send_probe = tcp_send_probe,
	.recv_probe = tcp_recv_probe,
	.expire_probe = tcp_expire_probe,
};

