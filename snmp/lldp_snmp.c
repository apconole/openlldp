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
#include "lldp.h"
#include "lldp_mod.h"
#include "messages.h"
#include "eloop.h"
#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "snmp/snmp_agent.h"
#include "snmp/ieee_mib.h"
#include "include/lldpad_snmp.h"

#include <net-snmp/net-snmp-config.h>

#include <net-snmp/agent/ds_agent.h>
#include <net-snmp/library/default_store.h>
#include <net-snmp/library/snmp_api.h>
#include <net-snmp/library/snmp_client.h>
#include <net-snmp/library/snmp_secmod.h>
#include <net-snmp/library/mib.h>
#include <net-snmp/library/snmp_logging.h>
#include <net-snmp/library/snmp_assert.h>
#include <net-snmp/pdu_api.h>

extern int snmp_do_nl(void);

static void refresh_snmp_data(void *, void *);

static int size;
static fd_set *sfds;
static int numfds;  /** max fd+1 returend from snmp_select_info()      */
static long lastcompid = 0;

/**********************
 * MIB SECTION
 **********************/

/**
 * Return bridge structure for given bridge interface
 */
struct ieee_bridge_mib_list *ieee_bridge_data(char *ifname)
{
	struct ieee_bridge_mib_list *lentry;

	LIST_FOREACH(lentry, &ieee_brl_head, entries) {
		if (!strncmp(lentry->bridge, ifname, strlen(ifname)) &&
		    !strncmp(lentry->bridge, ifname, strlen(lentry->bridge)))
			return lentry;
	}

	return NULL;
}

void snmp_clean_data(void)
{
	struct ieee_bridge_mib_list *lentry;
	struct bridge_interface_list *bil;
	struct bridge_list *bl;
	struct netdev_list *ndl;

	while (!LIST_EMPTY(&ieee_brl_head)) {
		lentry = LIST_FIRST(&ieee_brl_head);

		LIST_REMOVE(lentry, entries);

		ieee8021BridgeBaseTable_removeEntry(
				table_data_ieee8021BridgeBaseTable,
				lentry->row);

		while(!LIST_EMPTY(&lentry->brifl_head)) {
			bil = LIST_FIRST(&lentry->brifl_head);

			LIST_REMOVE(bil, entries);

			free(bil->name);
			free(bil->path);
			free(bil);
		}

		free(lentry->bridge);
		free(lentry->bridge_mac_file);
		free(lentry->brif_dir);
		free(lentry);
	}

	while (!LIST_EMPTY(&bridgel_head)) {
		bl = LIST_FIRST(&bridgel_head);

		LIST_REMOVE(bl, entries);

		free(bl->name);
		free(bl->path);
		free(bl);
	}

	while (!LIST_EMPTY(&netdevl_head)) {
		ndl = LIST_FIRST(&netdevl_head);

		LIST_REMOVE(ndl, entries);

		free(ndl->name);
		free(ndl->path);
		free(ndl);
	}
}

void snmp_deinit_agent(void)
{
	LLDPAD_INFO("%s[SNMP-AGENT] shutting down subagent.\n", SNMPTAG);
	free(sfds);
}

/**
 * Prints the linked list IEEE bridge entries
 *
 * Only called if LOG_DEBUG level is set
 */
void print_ibr_list(void)
{
	struct ieee_bridge_mib_list *lentry;

	LLDPAD_DBG("%s[LIST OF IEEE BRIDGE TABLES]\n", SNMPTAG);

	LIST_FOREACH(lentry, &ieee_brl_head, entries)
		LLDPAD_DBG("%s%20s\n", SNMPTAG, lentry->bridge);
}

/**
 * Remove old IEEE bridge devices from list
 */
static void cleanup_ibr_list(void)
{
	struct ieee_bridge_mib_list *lentry, *safe;

    if (LIST_EMPTY(&ieee_brl_head)) {
        LLDPAD_DBG("Unable to get snmp ibr devices\n");
        return;
    }

	LIST_FOREACH_SAFE(safe, lentry, &ieee_brl_head, entries) {
		if (lentry->active == 0) {
			LIST_REMOVE(lentry, entries);

			ieee8021BridgeBaseTable_removeEntry(
				table_data_ieee8021BridgeBaseTable,
				lentry->row);

			free(lentry->bridge);
			free(lentry->bridge_mac_file);
			free(lentry->brif_dir);
			free(lentry);
		}
	}
}

static void update_ieee8021BridgeBaseTable(struct ieee_bridge_mib_list *lentry)
{
	lentry->entry->ieee8021BridgeBaseNumPorts = lentry->num_ports;
	memcpy(lentry->entry->ieee8021BridgeBaseBridgeAddress, lentry->mac, 6);
}

static void update_ibr_entries(struct ieee_bridge_mib_list *lentry)
{
	struct link_rtnl_list *lrd;

	LIST_FOREACH(lrd, &linkrtl_head, entries) {
		if (!strncmp(lrd->ifname, lentry->bridge, strlen(lentry->bridge)) &&
		    !strncmp(lrd->ifname, lentry->bridge, strlen(lrd->ifname))) {
			memcpy(lentry->mac, lrd->mac, 6);
			break;
		}
	}
}

/**
 * Handle new/active IEEE bridge devices
 */
static void update_ibr_list(struct bridge_list *bl)
{
	struct ieee_bridge_mib_list *lentry;

	LIST_FOREACH(lentry, &ieee_brl_head, entries) {
		if (!strncmp(bl->name, lentry->bridge, strlen(lentry->bridge)) &&
		    !strncmp(bl->name, lentry->bridge, strlen(bl->name))) {
			lentry->num_ports = bl->num_ports;
			update_ibr_entries(lentry);
			update_ieee8021BridgeBaseTable(lentry);
			lentry->active = 1;

			return;
		}
	}

	lentry = calloc(1, sizeof(struct ieee_bridge_mib_list));
	if (!lentry) {
		LLDPAD_ERR("%s%s:%s calloc failed\n",
			   SNMPTAG, __func__, bl->name);
		return;
	}

	LIST_INIT(&lentry->brifl_head);

	lentry->bridge = strndup(bl->name, strlen(bl->name) + 1);
	update_ibr_entries(lentry);
	lentry->active = 1;
	lentry->compid = bl->compid;
	lentry->num_ports = bl->num_ports;

	LIST_INSERT_HEAD(&ieee_brl_head, lentry, entries);

	ieee8021BridgeBaseTable_createEntry(table_data_ieee8021BridgeBaseTable,
					    lentry->compid, lentry);
	return;
}

/**
 * Set all linked list entries to not active
 */
static void prepare_ibr_list(void)
{
	struct ieee_bridge_mib_list *lentry;

	LIST_FOREACH(lentry, &ieee_brl_head, entries)
		lentry->active = 0;
}

/**
 * Init IEEE bridge data
 */
static void init_lentry_data()
{
	struct bridge_list *bl;

	prepare_ibr_list();

	LIST_FOREACH(bl, &bridgel_head, entries)
		update_ibr_list(bl);

	cleanup_ibr_list();

	if (loglvl == LOG_DEBUG)
		print_ibr_list();
}

/**
 * Init SNMP data
 */
static void init_snmp_data(void)
{
	init_lentry_data();
}

/**
 * Prints the bridge linked list
 *
 * Only called if LOG_DEBUG level is set
 */
void print_bridge_list(void)
{
	struct bridge_list *bl;

	LLDPAD_DBG("%s[LIST OF BRIDGE DEVICES]\n", SNMPTAG);

	LIST_FOREACH(bl, &bridgel_head, entries)
		LLDPAD_DBG("%s%20s\n", SNMPTAG, bl->name);
}

/**
 * Remove old bridge devices from list
 */
static void cleanup_bridge_device_list(void)
{
	struct bridge_list *bl, *safe;

    if (LIST_EMPTY(&bridgel_head)) {
        LLDPAD_DBG("Unable to get snmp bridge devices\n");
        return;
    }

	LIST_FOREACH_SAFE(safe, bl, &bridgel_head, entries) {
		if (bl->active == 0) {
			LIST_REMOVE(bl, entries);

			free(bl->name);
			free(bl->path);
			free(bl);
		}
	}
}

/**
 * Handle new/active bridge devices
 */
static void update_bridge_device_list(char *ifname, char *path)
{
	int rbrif;
	int num_ports;
	struct bridge_list *bl;
	struct dirent **namelist;
	char *brif;

	LIST_FOREACH(bl, &bridgel_head, entries) {
		if (!strncmp(ifname, bl->name, strlen(ifname)) &&
		    !strncmp(ifname, bl->name, strlen(bl->name))) {
			num_ports = scandir(bl->path, &namelist, 0, 0);
			if (num_ports < 0) {
				LLDPAD_ERR("%s%s:%s scandir failed (%d)!",
					   SNMPTAG, __func__, ifname,
					   num_ports);
				goto out2;
			}

			if (num_ports > 1)
				bl->num_ports = num_ports - 2;
			bl->active = 1;

			while (num_ports--) {
				free(namelist[num_ports]);
			}
			free(namelist);

			return;
		}
	}

	if (lastcompid >= MAX_COMP_ID)
		goto out;

	size = strlen(path)+sizeof(BRIF);
	brif = calloc(1, size);
	if (brif == NULL)
		goto out_err;

	snprintf(brif, size, "%s%s", path, BRIF);

	rbrif = access(brif, R_OK);
	if (rbrif == 0) {
		bl = calloc(1, sizeof(struct bridge_list));
		if (bl == NULL)
			goto out_err3;

		bl->name = calloc(1, strlen(ifname) + 1);
		if (bl->name == NULL)
			goto out_err2;

		memcpy(bl->name, ifname, strlen(ifname) + 1);

		bl->path = calloc(1, strlen(brif) + 1);
		if (bl->path == NULL)
			goto out_err1;
		memcpy(bl->path, brif, strlen((brif)) + 1);

		num_ports = scandir(bl->path, &namelist, 0, 0);
		if (num_ports < 0) {
			LLDPAD_ERR("%s%s:%s scandir failed (%d)!",
				  SNMPTAG, __func__, ifname, num_ports);
			goto out2;
		}
		bl->num_ports = num_ports - 2;

		bl->active = 1;
		bl->compid = ++lastcompid;

		LIST_INSERT_HEAD(&bridgel_head, bl, entries);

		while (num_ports--) {
			free(namelist[num_ports]);
		}
		free(namelist);
	}

	free(brif);
	return;

out:
	LLDPAD_ERR("%s%s:%s couldn't determine a valid component (%ld)!",
		   SNMPTAG, __func__, ifname, lastcompid);
out2:
	return;

out_err1:
	free(bl->name);
out_err2:
	free(bl);
out_err3:
	free(brif);
out_err:
	LLDPAD_ERR("%s%s:%s calloc %d failed\n",
		   SNMPTAG, __func__, ifname, size);
}

/**
 * Set all linked list entries to not active
 */
static void prepare_bridge_device_list(void)
{
	struct bridge_list *bl;

	LIST_FOREACH(bl, &bridgel_head, entries)
		bl->active = 0;
}

/**
 * Init linked list of bridges present on the system
 */
static void init_bridge_list(void)
{
	struct netdev_list *nl;

	prepare_bridge_device_list();

	LIST_FOREACH(nl, &netdevl_head, entries)
		update_bridge_device_list(nl->name, nl->path);

	cleanup_bridge_device_list();

	if (loglvl == LOG_DEBUG)
		print_bridge_list();
}

/**
 * prints the netdev linked list
 *
 * only called if log_debug level is set
 */
void print_netdev_list(void)
{
	struct netdev_list *nl;

	LLDPAD_DBG("%s[list of network devices]\n", SNMPTAG);

	LIST_FOREACH(nl, &netdevl_head, entries)
		LLDPAD_DBG("%s%20s\n", SNMPTAG, nl->name);
}

/**
 * remove old network devices from list
 */
static void cleanup_net_device_list(void)
{
	struct netdev_list *nl, *safe;

    if (LIST_EMPTY(&netdevl_head)) {
        LLDPAD_DBG("Unable to get snmp net devices\n");
        return;
    }

	LIST_FOREACH_SAFE(safe, nl, &netdevl_head, entries) {
		if (nl->active == 0) {
			LIST_REMOVE(nl, entries);

			free(nl->name);
			free(nl->path);
			free(nl);
		}
	}
}

/**
 * handle new/active network devices
 *
 * add new network devices to the linked list as active
 * device. also reset the active flag to active to tell
 * that the device is still preseent.
 */
void update_net_device_data(char *ifname)
{
	struct netdev_list *nl;

	LIST_FOREACH(nl, &netdevl_head, entries) {
		if (!strncmp(nl->name, ifname, strlen(nl->name)) &&
		    !strncmp(nl->name, ifname, strlen(ifname))) {
			nl->active = 1;
			return;
		}
	}

	nl = calloc(1, sizeof(struct netdev_list));
	if (!nl)
		goto out_err;

	size = strlen(ifname) + 1;
	nl->name = calloc(1, size);
	if (!nl->name)
		goto out_err2;
	memcpy(nl->name, ifname, size);

	size += strlen(SYS_CLASS_NET);
	nl->path = calloc(1, size);
	if (!nl->path)
		goto out_err1;
	snprintf(nl->path, size, "%s%s", SYS_CLASS_NET, nl->name);

	nl->active = 1;

	LIST_INSERT_HEAD(&netdevl_head, nl, entries);

	return;

out_err1:
	free(nl->name);
out_err2:
	free(nl);
out_err:
	LLDPAD_ERR("%s%s:%s calloc %d failed\n",
		   SNMPTAG, __func__, ifname, size);
}

/**
 * set all linked list entries to not active
 */
static void prepare_net_device_list(void)
{
	struct netdev_list *nl;

	LIST_FOREACH(nl, &netdevl_head, entries)
		nl->active = 0;
}

/**
 * init linked list of network devices present on the system
 */
static void init_netdev_list(void)
{
	struct link_rtnl_list *lrd;

	prepare_net_device_list();

	snmp_do_nl();

	LIST_FOREACH(lrd, &linkrtl_head, entries)
		update_net_device_data(lrd->ifname);

	cleanup_net_device_list();

	if (loglvl == LOG_DEBUG)
		print_netdev_list();

	return;
}

/**
 * network init section
 */
static void init_net_data(void)
{
	init_netdev_list();     /** all network devices */
	init_bridge_list();     /** bridge devices */
}

/**
 * Initilize basic data
 */
static void init_base_data_structures(void)
{
	LIST_INIT(&linkrtl_head);
	LIST_INIT(&netdevl_head);
	LIST_INIT(&bridgel_head);
	LIST_INIT(&ieee_brl_head);
}

/**
 * Set up basic data structures
 */
static void init_data(void)
{
	init_base_data_structures();
	init_net_data();	/* set up network data */
	init_snmp_data();       /* set up mib data */
}

/**
 * Initializes all necessary data befor starting SNMP subagent
 */
static void init(void)
{
	init_data();
	/* add all future MIB table initialization data here */
}

/**
 * Poll function to update/cleanup SNMP data
 */
static void refresh_snmp_data(UNUSED void *eloop_data, UNUSED void *user_ctx)
{
	LLDPAD_DBG("%s%s: [DEBUG] updating mib data\n", SNMPTAG, __func__);

	init_net_data();
	init_snmp_data();

	eloop_register_timeout(10, 0, refresh_snmp_data, NULL, NULL);
}

/**
 * Check if we have lost one of our snmp fds
 */
int snmp_fd(fd_set *rfds)
{
	int i;

	for (i = 0; i < numfds; i++)
		if (FD_ISSET(i, sfds) && FD_ISSET(i, rfds))
			if (fcntl(i, F_GETFD) == -1)
				goto out_clean;
	return 0;

	out_clean:
		for (i = 0; i < numfds; i++)
		if (FD_ISSET(i, sfds))
			eloop_unregister_read_sock(i);

	LLDPAD_WARN("%s%s: [SNMP-AGENT] ", SNMPTAG, __func__);
	LLDPAD_WARN("lost connection to snmpd. ");
	LLDPAD_WARN("Please, restart lldpd daemon!\n");

	return -1;
}

/**
 * Get SNMP sockets to read
 */
static void this_snmp_read(int sock, UNUSED void *eloop_ctx,
			   UNUSED void *sock_ctx)
{
	fd_set msfds;

	FD_ZERO(&msfds);
	FD_SET(sock, &msfds);
	if (FD_ISSET(sock, &msfds))
		snmp_read(&msfds);
}

/**
 * Main snmp sub-agent function
 */
void snmp_init_agent(void)
{
	struct timeval timeout = { 0, 0 }, *tvp = &timeout;
	int i;
	int rc_nfds;  /** number of fds returned from snmp_select_info() */
	int fakeblock = 0;

	LLDPAD_INFO("%s%s: [SNMP-AGENT] initializing subagent\n",
		    SNMPTAG, __func__);

	/* obtain initial system data */
	init();

	/* register subagent/mib tables */
	mib_subagent();
	LLDPAD_INFO("%s%s: [SNMP-AGENT] mib_subagent\n", SNMPTAG, __func__);

	sfds = malloc(sizeof(fd_set));
	if (sfds == NULL)
		goto out;
	FD_ZERO(sfds);

	rc_nfds = snmp_select_info(&numfds, sfds, tvp, &fakeblock);
	if (!rc_nfds) {
		LLDPAD_ERR("%s%s: [ERROR] snmp_select_info() failed! %d %d\n",
			   SNMPTAG, __func__, rc_nfds, numfds);
		goto out;
	}

	for (i = 0; i < numfds; i++)
		if (FD_ISSET(i, sfds))
			eloop_register_read_sock(i, this_snmp_read, NULL, NULL);

	LLDPAD_INFO("%s%s: [SNMP-AGENT] init done", SNMPTAG, __func__);
	refresh_snmp_data(NULL, NULL);
	return;
out:
	free(sfds);
}

struct lldp_module *lldpad_snmp_register(void);
void lldpad_snmp_unregister(struct lldp_module *mod);

static const struct lldp_mod_ops snmpmod_ops =  {
	.lldp_mod_register 	= lldpad_snmp_register,
	.lldp_mod_unregister 	= lldpad_snmp_unregister,
};

struct lldp_module *lldpad_snmp_register(void)
{
	struct lldp_module *mod = calloc(1, sizeof(*mod));
	if (!mod) {
		LLDPAD_ERR("failed to alloc snmp agent module\n");
		goto out;
	}

	snmp_init_agent();
	mod->id = LLDP_MOD_SNMP;
	mod->ops = &snmpmod_ops;
	LLDPAD_DBG("%s:done (initialized snmp mod)\n", __func__);

out:
	return mod;
}

void lldpad_snmp_unregister(struct lldp_module *mod)
{
	snmp_deinit_agent();
	free(mod);
	LLDPAD_DBG("%s:done (uninit agent)\n", __func__);
}
