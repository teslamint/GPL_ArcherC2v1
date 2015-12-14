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
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <errno.h>
#include <linux/types.h>
#include <linux/errqueue.h>

#include "traceroute.h"


static sockaddr_any dest_addr = {{ 0, }, };
static u_int16_t seq = 1;
static u_int16_t ident = 0;

static char *data;
static size_t data_len = 0;

static int icmp_sk = -1;
static int last_ttl = 0;


static u_int16_t in_cksum (const void *ptr, size_t len) {
	const u_int16_t *p = (const u_int16_t *) ptr;
	unsigned int sum = 0;
	u_int16_t res;

	while (len > 1) {
	    sum += *p++;
	    len -= 2;
	}

	if (len)
	    sum += htons (*((unsigned char *) p) << 8);

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	res = ~sum;
	if (!res)  res = ~0;

	return res;
}


static int icmp_init (const char *host, const sockaddr_any *dest,
				unsigned int port_seq, size_t packet_len) {
	int i;
	int af = dest->sa.sa_family;

	dest_addr = *dest;
	dest_addr.sin.sin_port = 0;

	if (port_seq)  seq = port_seq;

	data_len = sizeof (struct icmphdr) + packet_len;
	data = malloc (data_len);
	if (!data)  error ("malloc");

        for (i = sizeof (struct icmphdr); i < data_len; i++)
                data[i] = 0x40 + (i & 0x3f);


	icmp_sk = socket (af, SOCK_RAW, (af == AF_INET) ? IPPROTO_ICMP
							: IPPROTO_ICMPV6);
	if (icmp_sk < 0)
		error ("socket");

	tune_socket (icmp_sk);

	add_poll (icmp_sk, POLLIN);

	ident = getpid () & 0xffff;
 
	return 0;
}


static void icmp_send_probe (probe *pb, int ttl) {
	int af = dest_addr.sa.sa_family;


	if (ttl != last_ttl) {

	    if (af == AF_INET) {
		if (setsockopt (icmp_sk, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
			error ("setsockopt IP_TTL");
	    }
	    else if (af == AF_INET6) {
		if (setsockopt (icmp_sk, SOL_IPV6, IPV6_UNICAST_HOPS,
						    &ttl, sizeof (ttl)) < 0
		)  error ("setsockopt IPV6_UNICAST_HOPS");
	    }

	    last_ttl = ttl;
	}


	if (af == AF_INET) {
	    struct icmp *icmp = (struct icmp *) data;

	    icmp->icmp_type = ICMP_ECHO;
	    icmp->icmp_code = 0;
	    icmp->icmp_cksum = 0;
	    icmp->icmp_id = htons (ident);
	    icmp->icmp_seq = htons (seq);

	    icmp->icmp_cksum = in_cksum (data, data_len);
	}
	else if (af == AF_INET6) {
	    struct icmp6_hdr *icmp6 = (struct icmp6_hdr *) data;

	    icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
	    icmp6->icmp6_code = 0;
	    icmp6->icmp6_cksum = 0;
	    icmp6->icmp6_id = htons (ident);
	    icmp6->icmp6_seq = htons(seq);

	    icmp6->icmp6_cksum = in_cksum (data, data_len);
	}


	pb->send_time = get_time ();

	if (sendto (icmp_sk, data, data_len, 0,
			    &dest_addr.sa, sizeof (dest_addr)) < 0
	)  error ("sendto");


	pb->seq = seq;

	seq++;

	return;
}


static void icmp_recv_probe (int sk, int revents, probe *probes,
						unsigned int num_probes) {
	int af = dest_addr.sa.sa_family;
	struct msghdr msg;
	sockaddr_any from;
	struct iovec iov;
	int n, type, code;
	u_int16_t recv_id, recv_seq;
	probe *pb;
	char buf[1024];		/*  enough, enough...  */
	char control[1024];


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

	n = recvmsg (sk, &msg, 0);
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

	    if (type == ICMP_ECHOREPLY) {
		    recv_id = ntohs (icmp->icmp_id);
		    recv_seq = ntohs (icmp->icmp_seq);
	    }
	    else if (type == ICMP_TIME_EXCEEDED ||
		     type == ICMP_DEST_UNREACH
	    ) {
		if (n < sizeof (struct iphdr) + sizeof (struct icmphdr))
			return;

		ip = (struct iphdr *) (((char *)icmp) + sizeof(struct icmphdr));
		hlen = ip->ihl << 2;

		if (n < hlen + sizeof (struct icmphdr))
			return;
		if (ip->protocol != IPPROTO_ICMP)
			return;

		icmp = (struct icmp *) (((char *) ip) + hlen);
		recv_id = ntohs (icmp->icmp_id);
		recv_seq = ntohs (icmp->icmp_seq);

	    } else
		return;
	}
	else {	    /*  AF_INET6   */
	    struct icmp6_hdr *icmp6 = (struct icmp6_hdr *) buf;

	    type = icmp6->icmp6_type;
	    code = icmp6->icmp6_code;

	    if (type == ICMP6_ECHO_REPLY) {
		    recv_id = ntohs (icmp6->icmp6_id);
		    recv_seq = ntohs (icmp6->icmp6_seq);
	    }
	    else if (type == ICMP6_TIME_EXCEEDED ||
		     type == ICMP6_DST_UNREACH
	    ) {
		struct ip6_hdr *ip6;

		if (n < 2 * sizeof (struct icmp6_hdr) + sizeof (struct ip6_hdr))
			return;

		ip6 = (struct ip6_hdr *) (icmp6 + 1);
		if (ip6->ip6_nxt != IPPROTO_ICMPV6)
			return;

		icmp6 = (struct icmp6_hdr *) (ip6 + 1);
		recv_id = ntohs (icmp6->icmp6_id);
		recv_seq = ntohs (icmp6->icmp6_seq);

	    } else
		return;
	}


	if (recv_id != ident)
		return;

	for (n = 0; n < num_probes && probes[n].seq != recv_seq; n++) ;
	if (n >= num_probes)  return;
	pb = &probes[n];


	memcpy (&pb->res, &from, sizeof (pb->res));

	if ((af == AF_INET && type == ICMP_ECHOREPLY) ||
	    (af == AF_INET6 && type == ICMP6_ECHO_REPLY)
	) {
		//printf("[ %s ] %d: ++++++++++last pkt??traceResult(%d)\n", __FUNCTION__, __LINE__, traceResult);
#ifdef CMM_MSG /* Yang Caiyong, 25Jul2012 */
		traceResult = TRACE_COMPLETE;
#endif /* CMM_MSG */
	    pb->final = 1;
	} else
	    parse_icmp_res (pb, type, code);

	pb->recv_time = get_timestamp (&msg);

	pb->recv_ttl = get_recv_ttl (&msg);


	pb->seq = -1;

	pb->done = 1;
}


static void icmp_expire_probe (probe *pb) {

	pb->seq = -1;

	pb->done = 1;
}


tr_ops icmp_ops = {
	.init = icmp_init,
	.send_probe = icmp_send_probe,
	.recv_probe = icmp_recv_probe,
	.expire_probe = icmp_expire_probe,
};
