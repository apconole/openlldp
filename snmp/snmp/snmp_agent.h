/*******************************************************************************

  Implementation of SNMP support
  (c) Copyright IBM Corp. 2012

  Author(s): Mijo Safradin <mijo at linux.vnet.ibm.com>

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

*******************************************************************************/

#include <lldp.h>
#include <sys/queue.h>
#include <qbg_vdp.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <linux/rtnetlink.h>

#include "../ieee8021BridgeBaseTable.h"
#include "../ieee8021BridgeEvbSys.h"

#define SNMPTAG	">>>"

#define SYS_CLASS_NET		"/sys/class/net/"
#define SYS_DEVICES_VIRTUAL_NET	"/sys/devices/virtual/net/"
#define BRIF			"/brif"
#define MAC_FILE		"/address"
#define PORT_NO_FILE		"/brport/port_no"
#define IFINDEX_FILE		"/ifindex"
#define BRIDGE_MAC_FILE(b)	VNETDIR b MAC_FILE

#define DOT1DNULL			0x00 /* 00000000 */
#define DOT1DLOCALVLANCAPABLE		0x01 /* 00000001 bit(8) */
#define DOT1QCONFIGURABLEPVIDTAGGING	0x02 /* 00000010 bit(7) */
#define DOT1QHYBRIDCAPABLE		0x04 /* 00000100 bit(6) */
#define DOT1QSVLCAPABLE			0x08 /* 00001000 bit(5) */
#define DOT1QIVLCAPABLE			0x10 /* 00010000 bit(4) */
#define DOT1QSTATICENTRYINDIVIDUALPORT	0x20 /* 00100000 bit(3) */
#define DOT1DTRAFFICCLASSES		0x40 /* 01000000 bit(2) */
#define DOT1DEXTENDEDFILTERINGSERVICES	0x80 /* 10000000 bit(1) */

#define STRING_SIZE 256
#define MAX_COMP_ID 0xFFFFFFFF

extern void init_ieee8021BridgeBaseTable(void);
extern void init_ieee8021BridgeEvbSys(void);
extern void ieee8021BridgeBaseTable_removeEntry(netsnmp_tdata *, netsnmp_tdata_row *);
extern int mib_subagent(void);
extern int get_evbsystype(void);

int evb_subagent(void);
void evb_subagent_shutdown(void);

fd_set *snmp_fds;

/**
 * List of bridge interfaces for given bridge
 */
struct bridge_interface_list {
	unsigned port_no;
	unsigned ifindex;
	char *name;
	char *path;

	struct ieee8021BridgeBasePortTable_entry *entry;

	LIST_ENTRY(bridge_interface_list) entries;
};

/**
 * The IEEE802.1 BRIDGE MIB base structure
 *
 * Each bridge on the system is represented by it's
 * own ieee_bridge_mib structure.
 */
struct ieee_bridge_mib_list {
	int		active;
	long		compid;

	char		*bridge;
	char		*bridge_mac_file;
	char		*brif_dir;

	unsigned char	devCapa[8];
	u8		mac[6];
	int		num_ports;

	netsnmp_tdata_row	*row;

	struct ieee8021BridgeBaseTable_entry
				*entry;

	LIST_HEAD(brif_list_head, bridge_interface_list)
				brifl_head;

	LIST_ENTRY(ieee_bridge_mib_list)
				entries;
};

LIST_HEAD(ieee_bridge_mib_head, ieee_bridge_mib_list) ieee_brl_head;

/**
 * Linked list structure of network bridges
 */
struct bridge_list {
	int active;
	long compid;

	int num_ports;

	char *name;
	char *path;

	LIST_ENTRY(bridge_list) entries;
};

LIST_HEAD(bridge_list_head, bridge_list) bridgel_head;

/**
 * Linkel list structure of network devices
 */
struct netdev_list {
	int active;

	char *name;
	char *path;

	LIST_ENTRY(netdev_list) entries;
};

LIST_HEAD(netdev_list_head, netdev_list) netdevl_head;

/**
 * Linkes list with information about a specific network interface
 *
 *
 * Implemented network interface information
 * =========================================
 *
 *      struct ifinfomsg
 *	      -> address family
 *	      -> device type
 *	      -> interface index
 *	      -> device flags
 *	      -> change mask
 *
 *      routing attributes
 *	      -> l2addr
 *	      -> ifname
 *
 */
struct link_rtnl_list {
	struct ifinfomsg *iim;

	int active;

	u8 mac[6];

	char l2addr[MAC_ADDR_STRLEN];
	char *ifname;

	LIST_ENTRY(link_rtnl_list) entries;
};

LIST_HEAD(link_rtnl_head, link_rtnl_list) linkrtl_head;

netsnmp_tdata *table_data_ieee8021BridgeBaseTable;
netsnmp_tdata *table_data_ieee8021BridgeBasePortTable;
