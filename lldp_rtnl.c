/*******************************************************************************

  LLDP Agent Daemon (LLDPAD) Software
  Copyright(c) 2007-2010 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  open-lldp Mailing List <lldp-devel@open-lldp.org>

*******************************************************************************/

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include "linux/netlink.h"
#include "linux/rtnetlink.h"
#include "linux/dcbnl.h"
#include "linux/if.h"
#include "lldp_util.h"
#include "lldp_rtnl.h"
#include "messages.h"
#include "lldp.h"
#if HAVE_SNMP
#include "snmp/snmp/snmp_agent.h"
#endif

#define NLMSG(c) ((struct nlmsghdr *) (c))

#define NLMSG_SIZE 1024

typedef int rtnl_handler(struct nlmsghdr *nh, void *arg);

/**
 * rtnl_recv - receive from a routing netlink socket
 * @s: routing netlink socket with data ready to be received
 *
 * Returns:	0 when NLMSG_DONE is received
 * 		<0 on error
 * 		>0 when more data is expected
 */
static int rtnl_recv(int s, UNUSED rtnl_handler *fn, UNUSED void *arg)
{
	char buf[8192];
	struct nlmsghdr *nh;
	int res;
	int rc = 0;
	unsigned len;
	bool more = false;

more:
	res = recv(s, buf, sizeof(buf), 0);
	if (res < 0)
		return res;

	len = res;
	for (nh = NLMSG(buf); NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
		if (nh->nlmsg_flags & NLM_F_MULTI)
			more = true;

		switch (nh->nlmsg_type) {
		case NLMSG_NOOP:
			break;
		case NLMSG_ERROR:
			rc = ((struct nlmsgerr *)NLMSG_DATA(nh))->error;
			break;
		case NLMSG_DONE:
			more = false;
			break;
		default:
			break;
		}
	}
	if (more)
		goto more;
	return rc;
}

#define NLMSG_TAIL(nmsg) \
	((struct rtattr *)(((void *)(nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

static void add_rtattr(struct nlmsghdr *n, int type, const void *data, int alen)
{
	struct rtattr *rta = NLMSG_TAIL(n);
	int len = RTA_LENGTH(alen);

	rta->rta_type = type;
	rta->rta_len = len;
	if (data)
		memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
}

static ssize_t rtnl_send_linkmode(int s, int ifindex,
				  const char *ifname, __u8 linkmode)
{
	struct {
		struct nlmsghdr nh;
		struct ifinfomsg ifm;
		char attrbuf[
			RTA_SPACE(IFNAMSIZ)	/* IFNAME */
			+ RTA_SPACE(1)];	/* LINKMODE */
	} req = {
		.nh = {
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
			.nlmsg_type = RTM_SETLINK,
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
		},
		.ifm = {
			.ifi_index = ifindex,
		},
	};

	if (ifname)
		add_rtattr(&req.nh, IFLA_IFNAME, ifname, strlen(ifname));
	add_rtattr(&req.nh, IFLA_LINKMODE, &linkmode, 1);

	return send(s, &req, req.nh.nlmsg_len, 0);
}

int set_linkmode(int ifindex, const char *ifname, __u8 linkmode)
{
	int s;
	int rc;

	s = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (s < 0)
		return s;
	rc = rtnl_send_linkmode(s, ifindex, ifname, linkmode);
	if (rc < 0)
		goto out;
	rc = rtnl_recv(s, NULL, NULL);
out:
	close(s);
	return rc;
}

static ssize_t rtnl_send_operstate(int s, int ifindex,
				   char *ifname, __u8 operstate)
{
	struct {
		struct nlmsghdr nh;
		struct ifinfomsg ifm;
		char attrbuf[
			RTA_SPACE(IFNAMSIZ)	/* IFNAME */
			+ RTA_SPACE(1)];	/* OPERSTATE */
	} req = {
		.nh = {
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
			.nlmsg_type = RTM_SETLINK,
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
		},
		.ifm = {
			.ifi_index = ifindex,
		},
	};

	if (ifname)
		add_rtattr(&req.nh, IFLA_IFNAME, ifname, strlen(ifname));
	add_rtattr(&req.nh, IFLA_OPERSTATE, &operstate, 1);

	return send(s, &req, req.nh.nlmsg_len, 0);
}

static ssize_t rtnl_recv_operstate(int s, int ifindex,
				   char *ifname, __u8 *operstate)
{
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct rtattr *rta;
	int attrlen;
	int rc = -1; 

	nlh = malloc(NLMSG_SIZE);
	if (!nlh)
		return rc;

	memset(nlh, 0, NLMSG_SIZE);

	/* send ifname request */
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nlh->nlmsg_type = RTM_GETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST;

	ifi = NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = ifindex;	

	if (ifname)
		add_rtattr(nlh, IFLA_IFNAME, ifname, strlen(ifname));

	rc = send(s, nlh, nlh->nlmsg_len, 0);
	if (rc < 0)
		goto out;

	/* recv ifname reply */
	memset(nlh, 0, NLMSG_SIZE);
	rc = recv(s, (void *) nlh, NLMSG_SIZE, MSG_DONTWAIT);
	if (rc < 0)
		goto out;
	ifi = NLMSG_DATA(nlh);
	rta = IFLA_RTA(ifi);
	attrlen = NLMSG_PAYLOAD(nlh, 0) - sizeof(struct ifinfomsg);
	while (RTA_OK(rta, attrlen)) {
		if (rta->rta_type == IFLA_OPERSTATE)
			memcpy(operstate, RTA_DATA(rta), sizeof(__u8));
		rta = RTA_NEXT(rta, attrlen);
	}

out:
	free(nlh);
	return rc;
}

int set_operstate(char *ifname, __u8 operstate)
{
	int s;
	int rc;
	int ifindex = 0;

	s = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (s < 0)
		return s;
	rc = rtnl_send_operstate(s, ifindex, ifname, operstate);
	if (rc < 0)
		goto out;
	rc = rtnl_recv(s, NULL, NULL);
out:
	close(s);
	return rc;
}

int get_operstate(char *ifname)
{
	int s;
	int ifindex;
	__u8 operstate = IF_OPER_UNKNOWN;

	ifindex = get_ifidx(ifname);
	s = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (s < 0)
		return s;

	rtnl_recv_operstate(s, ifindex, ifname, &operstate);
	close(s);
	return operstate;
}

int get_perm_hwaddr(const char *ifname, u8 *buf_perm, u8 *buf_san)
{
	int s;
	struct rtattr *rta;
	int rc = 0;

	struct {
		struct nlmsghdr nh;
		struct dcbmsg d;
		union {
			struct rtattr rta;
			char attrbuf[RTA_SPACE(2 * IFNAMSIZ)];
		} u;
	} req = {
		.nh = {
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct dcbmsg)),
			.nlmsg_type = RTM_GETDCB,
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
		},
		.d = {
			.cmd = DCB_CMD_GPERM_HWADDR,
			.dcb_family = AF_UNSPEC,
			.dcb_pad = 0,
		},
	};


	s = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (s < 0) {
		rc = -EIO;
		goto out_nosock;
	}

	add_rtattr(&req.nh, DCB_ATTR_IFNAME, ifname, strlen(ifname) + 1);
	add_rtattr(&req.nh, DCB_ATTR_PERM_HWADDR, NULL, 0);

	rc = send(s, &req.nh, req.nh.nlmsg_len, 0);
	if (rc < 0)
		goto out;

	/* recv ifname reply */
	memset(&req, 0, sizeof(req));
	rc = recv(s, (void *) &req, sizeof(req), MSG_DONTWAIT);
	if (rc < 0)
		goto out;

	if (req.d.cmd != DCB_CMD_GPERM_HWADDR) {
		rc = -EIO;
		goto out;
	}

	rta = &req.u.rta;
	if (rta->rta_type != DCB_ATTR_PERM_HWADDR) {
		/* Do we really want to code up an attribute parser?? */
		rc = -EIO;
		goto out;
	}

	memcpy(buf_perm, RTA_DATA(rta), ETH_ALEN);
	memcpy(buf_san, RTA_DATA(rta) + ETH_ALEN, ETH_ALEN);

	rc = 0;
out:
	close(s);
out_nosock:
	return rc;
}

#if HAVE_SNMP
static void prepare_lrt_device_list(void)
{
	struct link_rtnl_list *lrd;

	LIST_FOREACH (lrd, &linkrtl_head, entries)
		lrd->active = 0;
}

static void cleanup_lrt_device_list(void)
{
	struct link_rtnl_list *lrd, *safe;

    if (LIST_EMPTY(&linkrtl_head)) {
        return;
    }

	LIST_FOREACH_SAFE (safe, lrd, &linkrtl_head, entries) {
		if (!lrd->active) {
			LIST_REMOVE(lrd, entries);

			free(lrd->ifname);
			free(lrd->iim);
			free(lrd);
		}
	}
}

static void snmp_parse_msg(struct nlmsghdr *h)
{
	struct ifinfomsg *ifm = (void *)h + NLMSG_ALIGN(sizeof(struct nlmsghdr));
	struct link_rtnl_list *lrd, *old;
	char mac[MAC_ADDR_STRLEN] = {0};
	char *tmp_mac, *ifname = NULL;
	struct rtattr *attribute;
	struct ifinfomsg *iface;
	int len;

	iface = NLMSG_DATA(h);
	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(*iface));

	lrd = calloc(1, sizeof(struct link_rtnl_list));
	if (!lrd)
		return;

	lrd->iim = calloc(1, sizeof(struct ifinfomsg));
	if (!lrd->iim) {
		free(lrd);
		return;
	}

	for (attribute = IFLA_RTA(iface); RTA_OK(attribute, len);
		 attribute = RTA_NEXT(attribute, len)) {
		switch (attribute->rta_type) {
		case IFLA_ADDRESS:
			tmp_mac = (char *)RTA_DATA(attribute);
			print_mac(tmp_mac, mac);
			str2mac(mac, lrd->mac, sizeof(lrd->mac));
			break;
		case IFLA_IFNAME:
			if (ifname) {
				free(ifname);
			}
			ifname = (char *)RTA_DATA(attribute);
			lrd->ifname = strndup(ifname, strlen(ifname) + 1);
			break;
		default:
			break;
		}
	}

	LIST_FOREACH (old, &linkrtl_head, entries) {
		if (!strncmp(old->ifname, lrd->ifname, strlen(lrd->ifname)) &&
			!strncmp(old->ifname, lrd->ifname, strlen(old->ifname))) {
			old->active = 1;
			memcpy(old->iim, ifm, sizeof(struct ifinfomsg));

			free(lrd->ifname);
			free(lrd->iim);
			free(lrd);
			goto out;
		}
	}

	lrd->active = 1;
	memcpy(lrd->iim, ifm, sizeof(struct ifinfomsg));
	LIST_INSERT_HEAD(&linkrtl_head, lrd, entries);

out:
	return;
}

ssize_t snmp_recvfrom(const int fd, void *buf, size_t len)
{
	struct sockaddr_nl da;
	struct iovec iov = {
		.iov_base = buf,
		.iov_len  = len,
	};
	struct msghdr msg = {
		.msg_name = &da,
		.msg_namelen = sizeof(da),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = 0,
	};

	ssize_t ret = recvmsg(fd, &msg, 0);
	if (ret < 0)
		perror("snmp_recvfrom");

	return ret;
}

int snmp_do_nl(void) {
	struct rtgenmsg rt_hdr = { .rtgen_family = AF_PACKET, };
	struct nl_sock *handle;
	unsigned char *buf;
	int done = 0;
	int ret;

	handle = nl_socket_alloc();
	nl_connect(handle, NETLINK_ROUTE);
	ret = nl_send_simple(handle, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP,
			     &rt_hdr, sizeof(rt_hdr));
	if (ret < 0) {
		nl_close(handle);
		nl_socket_free(handle);
		return 1;
	}

	prepare_lrt_device_list();

	while (!done) {
		struct nlmsghdr *nlhb;

		ret = nl_recv(handle, NULL, &buf, NULL);
		nlhb = (struct nlmsghdr *) buf;
		if (ret > 0) {
			while(nlmsg_ok(nlhb, ret)) {
				switch(nlhb->nlmsg_type) {
					case 3:
						done++;
						break;
					case 16:
						snmp_parse_msg(nlhb);
						break;
					default:
						break;
				}
				nlhb = nlmsg_next(nlhb, &ret);
			}
		} else {
			done++; /*error on nlmsg recv*/
		}
	}

	cleanup_lrt_device_list();
	nl_close(handle);
	nl_socket_free(handle);

	return 0;
}
#endif
