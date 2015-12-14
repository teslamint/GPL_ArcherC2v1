#ifndef __LINUX_BRIDGE_EBT_FTOS_T_H
#define __LINUX_BRIDGE_EBT_FTOS_T_H

struct ebt_ftos_info
{
	int ftos;
	unsigned char mask;
	int target;
};
#define EBT_FTOS_TARGET "ftos"

/* Add by ZJ, 2013-11-14 */
#define FTOS_TARGET       0x01
#define FTOS_SETFTOS      0x02
#define FTOS_WMMFTOS      0x04
#define FTOS_8021QFTOS    0x08

#define DSCP_MASK_SHIFT   5
#define PRIO_LOC_NFMARK   16
#define PRIO_LOC_NFMASK   7
/* End add */

#endif
