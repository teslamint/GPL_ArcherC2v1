/*
    Copyright (c)  2006		    Dmitry K. Butskoy
				    <buc@citadel.stu.neva.ru>
    License:  GPL		

    See COPYING for the status of this software.
*/


union common_sockaddr {
	struct sockaddr sa;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
};
typedef union common_sockaddr sockaddr_any;

struct probe_struct {
	int done;
	int final;
	sockaddr_any res;
	double send_time;
	double recv_time;
	int recv_ttl;
	int sk;
	int seq;
	char err_str[16];	/*  assume enough   */
};
typedef struct probe_struct probe;

struct traceroute_operations {
	int (*init) (const char *host, const sockaddr_any *dest,
				unsigned int port_seq, size_t packet_len);
	void (*send_probe) (probe *pb, int ttl);
	void (*recv_probe) (int fd, int revents,
				probe *probes, unsigned int num_probes);
	void (*expire_probe) (probe *pb);
};
typedef struct traceroute_operations tr_ops;

extern tr_ops udp_ops, icmp_ops, tcp_ops;


#define DEF_UDP_PORT	33434
#define DEF_TCP_PORT	80

#ifdef CMM_MSG /* Yang Caiyong, 25Jul2012 */

typedef enum
{
	TRACE_HEAD			 = 0,
	TRACE_SUCC			 = 1,
	TRACE_FAILED		 = 2,
	TRACE_RESOLVE_FAILED = 3,
	TRACE_HOP_EXCEED	 = 4,
	TRACE_COMPLETE		 = 5
}TRACERT_ERROR_CODE;

extern int traceResult;
void send_result(int errCode, int responseTime, char *ip, char *result);

#endif /* CMM_MSG */


void error (const char *str) __attribute__((noreturn));

double get_time (void);
void tune_socket (int sk);
void parse_icmp_res (probe *pb, int type, int code);

void use_timestamp (int sk);
double get_timestamp (struct msghdr *msg);
void use_recv_ttl (int sk);
int get_recv_ttl (struct msghdr *msg);

void add_poll (int fd, int events);
void del_poll (int fd);

extern const char *get_as_path (const char *query);
