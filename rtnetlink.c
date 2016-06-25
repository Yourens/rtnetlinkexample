#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h> #include <string.h>

#include <net/if.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <pcap/pcap.h>

#include "xalloc.h"

int read_nl_sock(int sock, char *buf, int buf_len)
{
	int msg_len = 0;
	char *pbuf = buf;
	do {
		int len = recv(sock, pbuf, buf_len - msg_len, 0);
		if (len <= 0) {
			return -1;
		}
		struct nlmsghdr *nlhdr = (struct nlmsghdr *)pbuf;
		if (NLMSG_OK(nlhdr, ((unsigned int)len)) == 0 ||
						nlhdr->nlmsg_type == NLMSG_ERROR) {
			return -1;
		}
		if (nlhdr->nlmsg_type == NLMSG_DONE) {
			break;
		} else {
			msg_len += len;
			pbuf += len;
		}
		if ((nlhdr->nlmsg_flags & NLM_F_MULTI) == 0) {
			break;
		}
	} while (1);
	return msg_len;
}

int send_nl_req(uint16_t msg_type, uint32_t seq,
				void *payload, uint32_t payload_len)
{
	int sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (sock < 0) {
		return -1;
	}
	if (NLMSG_SPACE(payload_len) < payload_len) {
		close(sock);
		// Integer overflow
		return -1;
	}
	struct nlmsghdr *nlmsg;
	nlmsg = (struct nlmsghdr *) xmalloc(NLMSG_SPACE(payload_len));

	memset(nlmsg, 0, NLMSG_SPACE(payload_len));
	memcpy(NLMSG_DATA(nlmsg), payload, payload_len);
	nlmsg->nlmsg_type = msg_type;
	nlmsg->nlmsg_len = NLMSG_LENGTH(payload_len);
	nlmsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
	nlmsg->nlmsg_seq = seq;
	nlmsg->nlmsg_pid = getpid();

	if (send(sock, nlmsg, nlmsg->nlmsg_len, 0) < 0) {
		return -1;
	}
	free(nlmsg);
	return sock;
}

// gw and iface[IF_NAMESIZE] MUST be allocated
int _get_default_gw(char *addr, char *iface, const int family)
{
	struct rtmsg req;
	unsigned int nl_len;
	char buf[8192];
	struct nlmsghdr *nlhdr;

	if (!addr || !iface) {
		return -1;
	}

	// Send RTM_GETROUTE request
	memset(&req, 0, sizeof(req));
	req.rtm_family = family;
	int sock = send_nl_req(RTM_GETROUTE, 0, &req, sizeof(req));

	// Read responses
	nl_len = read_nl_sock(sock, buf, sizeof(buf));
	if (nl_len <= 0) {
		return -1;
	}

	// Parse responses
	nlhdr = (struct nlmsghdr *)buf;
	while (NLMSG_OK(nlhdr, nl_len)) {
		struct rtattr *rt_attr;
		struct rtmsg *rt_msg;
		int rt_len;
		int has_gw = 0;

		rt_msg = (struct rtmsg *) NLMSG_DATA(nlhdr);

		if ((rt_msg->rtm_family != family) || (rt_msg->rtm_table != RT_TABLE_MAIN)) {
			return -1;
		}

		rt_attr = (struct rtattr *) RTM_RTA(rt_msg);
		rt_len = RTM_PAYLOAD(nlhdr);
		while (RTA_OK(rt_attr, rt_len)) {
			switch (rt_attr->rta_type) {
			case RTA_OIF:
				if_indextoname(*(int *) RTA_DATA(rt_attr), iface);
				break;
			case RTA_GATEWAY:
				//gw->s_addr = *(unsigned int *) RTA_DATA(rt_attr);
				inet_ntop(family, RTA_DATA(rt_attr), addr,64);
				has_gw = 1;
				break;
			}
			rt_attr = RTA_NEXT(rt_attr, rt_len);
		}

		if (has_gw) {
			return 0;
		}
		nlhdr = NLMSG_NEXT(nlhdr, nl_len);
	}
	return -1;
}

int main(int argc, char *argv[]) {
	struct in6_addr gw_ip;

	char errbuf[PCAP_ERRBUF_SIZE];
	char *iface = pcap_lookupdev(errbuf);
	char addr[64];
	int family = -1;
	if(argc <2)
		exit(0);
	if(atoi(argv[1]) == 0)
		family = AF_INET;
	else if(atoi(argv[1]) == 1)
		family = AF_INET6;

	if(family == -1){
		printf("parameter error\n");
		printf("Usage: test [01]\n");
		exit(0);
	}
	memset(addr, 0, 64);
	_get_default_gw(addr, iface, family);
	printf("gateway: %s via iface: %s\n",addr, iface);
	
	return 0;
}
