/**
* Shows the network interfaces using RTNETLINK
*
* @author:   Asanga Udugama <adu@comnets.uni-bremen.de>
* @modified: Stian Skjelstad <stian@nixia.no>
* @date:     19-jul-2005
*
*/

#include <arpa/inet.h>
#include <inttypes.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// gcc -o if_show if_show.c

struct {
	struct nlmsghdr		nlmsg_info;
	struct ifaddrmsg	ifaddrmsg_info;
//	char			buffer[2048];
} netlink_req;

static int fd;

/**
* Send a request to NETLINK to send the ifc info
*/
static void send_ifc_read_request(const int family)
{
	int rtn;

	bzero(&netlink_req, sizeof(netlink_req));

	netlink_req.nlmsg_info.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	netlink_req.nlmsg_info.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	netlink_req.nlmsg_info.nlmsg_type = RTM_GETADDR;
	netlink_req.nlmsg_info.nlmsg_pid = getpid();

	netlink_req.ifaddrmsg_info.ifa_family = family;

	rtn = send (fd, &netlink_req, netlink_req.nlmsg_info.nlmsg_len, 0);
	if(rtn < 0)
	{
		perror ("send(): ");
		exit (1);
	}
}

/**
* Read the output sent by NETLINK for the get ifc list request given
* in function send_ifc_read_request()
*/
static void read_ifc_request_results(int pagesize, void (*on_data_handler)(struct nlmsghdr *nlmsg_ptr, int nlmsg_len))
{
	char read_buffer[pagesize];
	struct nlmsghdr *nlmsg_ptr;
	int nlmsg_len;

	while(1)
	{
		int rtn;

		bzero(read_buffer, pagesize);
		rtn = recv(fd, read_buffer, pagesize, 0);
		if(rtn < 0)
		{
			perror ("recv(): ");
			exit(1);
		}

		nlmsg_ptr = (struct nlmsghdr *) read_buffer;
		nlmsg_len = rtn;

		// fprintf (stderr, "received %d bytes\n", rtn);

		if (nlmsg_len < sizeof (struct nlmsghdr))
		{
			fprintf (stderr, "received an uncomplete netlink packet\n");
			exit (1);
		}

		if (nlmsg_ptr->nlmsg_type == NLMSG_DONE)
			break;

		on_data_handler (nlmsg_ptr, nlmsg_len);
	}
}

/**
* Extract each ifc entry and print
*/
void process_and_print(struct nlmsghdr *nlmsg_ptr, int nlmsg_len) 
{
	for(; NLMSG_OK(nlmsg_ptr, nlmsg_len); nlmsg_ptr = NLMSG_NEXT(nlmsg_ptr, nlmsg_len))
	{
		struct ifaddrmsg *ifaddrmsg_ptr;
		struct rtattr *rtattr_ptr;
		int ifaddrmsg_len;

		char anycast_str[INET6_ADDRSTRLEN];
		char ipaddr_str[INET6_ADDRSTRLEN];
		char localaddr_str[INET6_ADDRSTRLEN];
		char name_str[IFNAMSIZ];
		char bcastaddr_str[INET6_ADDRSTRLEN];
		char cacheinfo_str[128];
		char multicast_str[INET6_ADDRSTRLEN];
		char scope_str[16];

		ifaddrmsg_ptr = (struct ifaddrmsg *) NLMSG_DATA(nlmsg_ptr);

		anycast_str[0] = 0;
		ipaddr_str[0] = 0;
		localaddr_str[0] = 0;
		name_str[0] = 0;
		bcastaddr_str[0] = 0;
		cacheinfo_str[0] = 0;
		multicast_str[0] = 0;
		scope_str[0] = 0;

		rtattr_ptr = (struct rtattr *) IFA_RTA(ifaddrmsg_ptr);
		ifaddrmsg_len = IFA_PAYLOAD(nlmsg_ptr);

		if (ifaddrmsg_ptr->ifa_scope == RT_SCOPE_UNIVERSE)
			strcpy (scope_str, "global");
		else if (ifaddrmsg_ptr->ifa_scope == RT_SCOPE_SITE)
			strcpy (scope_str, "site");
		else if (ifaddrmsg_ptr->ifa_scope == RT_SCOPE_LINK)
			strcpy (scope_str, "link");
		else if (ifaddrmsg_ptr->ifa_scope == RT_SCOPE_HOST)
			strcpy (scope_str, "host");
		else if (ifaddrmsg_ptr->ifa_scope == RT_SCOPE_NOWHERE)
			strcpy (scope_str, "nowhere");
		else
			snprintf (scope_str, sizeof(scope_str), "%d", ifaddrmsg_ptr->ifa_scope);


		for(;RTA_OK(rtattr_ptr, ifaddrmsg_len); rtattr_ptr = RTA_NEXT(rtattr_ptr, ifaddrmsg_len)) {

			switch(rtattr_ptr->rta_type) {
			case IFA_ADDRESS:
				inet_ntop(ifaddrmsg_ptr->ifa_family, RTA_DATA(rtattr_ptr), ipaddr_str, sizeof(ipaddr_str));
				break;
			case IFA_LOCAL:
				inet_ntop(ifaddrmsg_ptr->ifa_family, RTA_DATA(rtattr_ptr), localaddr_str, sizeof(localaddr_str));
				break;
			case IFA_BROADCAST:
				inet_ntop(ifaddrmsg_ptr->ifa_family, RTA_DATA(rtattr_ptr), bcastaddr_str, sizeof(bcastaddr_str));
				break;
			case IFA_ANYCAST:
				inet_ntop(ifaddrmsg_ptr->ifa_family, RTA_DATA(rtattr_ptr), anycast_str, sizeof(anycast_str));
				break;
			case IFA_MULTICAST:
				inet_ntop(ifaddrmsg_ptr->ifa_family, RTA_DATA(rtattr_ptr), multicast_str, sizeof(multicast_str));
				break;
			case IFA_LABEL:
				snprintf(name_str, sizeof(name_str), "%s", (char *) RTA_DATA(rtattr_ptr));
				break;
			case IFA_CACHEINFO:
				{
					struct ifa_cacheinfo *ci =  (struct ifa_cacheinfo *) RTA_DATA(rtattr_ptr);
					char prefered [32];
					char valid[32];

					/* struct ifa_cacheinfo has four members
						__u32 ifa_prefered    how long this address can be in preferred  state, in seconds. When preferred time is finished, this IPv6 address  will stop 
communicating. (will not answer ping6, etc)
						__u32 ifa_valid       how long this prefix is valid, in seconds. When the valid time is over, the IPV6 address is removed.
						__u32 cstamp          created timestamp (hundreths of seconds)
						__u32 tstamp          updated timestamp (hundreths of seconds) This should change everytime this line changes
					*/
					if (ci->ifa_valid == 0xFFFFFFFFUL)
						strcpy (valid, "valid_lft forever");
					else
						snprintf (valid, sizeof (valid), "valid %"PRIu32"sec", ci->ifa_valid);

					if (ci->ifa_prefered == 0xFFFFFFFFUL)
						strcpy (prefered, "prefered_lft forever");
					else
						snprintf (prefered, sizeof (prefered), "prefered %"PRIu32"sec", ci->ifa_prefered);

					snprintf (cacheinfo_str, sizeof (cacheinfo_str), "%s %s", valid, prefered);
				}
				break;

			default:
				printf ("unknown rta_type: %d\n", (int)rtattr_ptr->rta_type);
				break; 

			}
		}

		if(strlen(ipaddr_str) != 0) {
			printf("%s/%d", ipaddr_str, ifaddrmsg_ptr->ifa_prefixlen);
		}

		if(strlen(localaddr_str) != 0) {
			printf(" local %s", localaddr_str);
		}

		if(strlen(bcastaddr_str) != 0) {
			printf(" broadcast %s", bcastaddr_str);
		}

		if (strlen(anycast_str) != 0) {
			printf (" anycast %s", anycast_str);
		}

		if (strlen(multicast_str) != 0) {
			printf (" multicast %s", multicast_str);
		}

		if(strlen(name_str) != 0) {
			printf(" dev %s %d", name_str, ifaddrmsg_ptr->ifa_index);
		} else {
			printf(" ifindex %d", ifaddrmsg_ptr->ifa_index);
		}

		printf ("\n");

		printf ("scope %s", scope_str);
		if (strlen(cacheinfo_str) != 0) {
			printf (" %s", cacheinfo_str);
		}

		printf ("\n");

		if (ifaddrmsg_ptr->ifa_flags & IFA_F_TEMPORARY)
			printf ("Address is temporary (Privacy Extensions RFC3041)\n");
		if (ifaddrmsg_ptr->ifa_flags & IFA_F_NODAD)
		{
			printf ("Duplicate Address Detection (DAD) is disabled\n");
			if (!(ifaddrmsg_ptr->ifa_flags & IFA_F_PERMANENT))
				printf ("\tBut IFA_F_PERMANENT is not set?\n");
		} else {
			if (ifaddrmsg_ptr->ifa_flags & IFA_F_OPTIMISTIC)
				printf ("Duplicate Address Detection (DAD) will be using Optimistic Mode when ran (RFC4429)\n");
			if (ifaddrmsg_ptr->ifa_flags & IFA_F_TENTATIVE)
				printf ("Duplicate Address Detection (DAD) is running, ordinary traffic not allowed yet\n");
			else if (ifaddrmsg_ptr->ifa_flags & IFA_F_DADFAILED)
				printf ("Duplicate Address Detection (DAD) failed\n");
			else if (ifaddrmsg_ptr->ifa_flags & IFA_F_PERMANENT)
				printf ("Duplicate Address Detection (DAD) was successfull and will not be ran again\n");
			else
				printf ("Duplicate Address Detection (DAD) is idle\n");
		}
		if (ifaddrmsg_ptr->ifa_flags & IFA_F_HOMEADDRESS)
			printf ("Address is a Movile IPv6 Home Address (RFC3775 Section 6.4, RFC3484 Section 5 Rule 4\n");
		if (ifaddrmsg_ptr->ifa_flags & IFA_F_DEPRECATED)
			printf ("Address is deprecated and will be removed soon (prefered timed out)\n");

		printf("\n");
	}
	printf("\n");
}

int main(int argc, char *argv[])
{
	int pagesize = sysconf(_SC_PAGESIZE);

	if (!pagesize)
		pagesize = 4096; /* Assume pagesize is 4096 if sysconf() failed */

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if(fd < 0)
	{
		perror ("socket(): ");
		exit(1);
	}

	printf ("**** IPv6 ****\n");

	send_ifc_read_request(AF_INET6);
	read_ifc_request_results(pagesize, process_and_print);

	printf ("**** IPv4 ****\n");

	send_ifc_read_request(AF_INET);
	read_ifc_request_results(pagesize, process_and_print);

	close(fd);

	exit(0);
}
