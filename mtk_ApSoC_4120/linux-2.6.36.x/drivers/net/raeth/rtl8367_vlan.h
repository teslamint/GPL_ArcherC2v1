#ifndef _RTL8367B_ASICDRV_VLAN_H_
#define _RTL8367B_ASICDRV_VLAN_H_

/****************************************************************/
/* Header File inclusion                                        */
/****************************************************************/
#include "rtl8367_types.h"

/****************************************************************/
/* Constant Definition                                          */
/****************************************************************/

#define LAN_VLAN_ID 	50
#define WAN_VLAN_ID 	51
#define LAN_VLAN_PVID	LAN_VLAN_ID
#define WAN_VLAN_PVID	WAN_VLAN_ID

#define RALINK_ETH_SW_BASE 0xB0110000

#define RTL8367B_PROTOVLAN_GIDX_MAX 3
#define RTL8367B_PROTOVLAN_GROUPNO  4

#define RTL8367B_VIDMAX                     0xFFF
#define RTL8367B_EVIDMAX                    0x1FFF
#define RTL8367B_PRIMAX                     7

#define RTK_MAX_PORT_MASK                           0xFF
#define RTK_IVL_MODE_FID                            0xFFFF
#define RTL8367B_FIDMAX                     0xF

#define RTL8367B_PORTMASK                   0xFF
#define RTL8367B_METERNO                    32
#define RTL8367B_METERMAX                   (RTL8367B_METERNO-1)

#define RTL8367B_PORTNO                     8
#define RTL8367B_PORTIDMAX                  (RTL8367B_PORTNO-1)

#define RTL8367B_REGBITLENGTH               16

#define    RTL8367B_TABLE_TYPE_MASK    0x7
#define    RTL8367B_COMMAND_TYPE_MASK    0x8

#define    RTL8367B_REG_TABLE_LUT_ADDR    0x0502
#define    RTL8367B_TABLE_ACCESS_STATUS_REG    		RTL8367B_REG_TABLE_LUT_ADDR
#define    RTL8367B_TABLE_LUT_ADDR_BUSY_FLAG_OFFSET    13

#define    RTL8367B_REG_TABLE_READ_DATA0    0x0520
#define    RTL8367B_TABLE_ACCESS_RDDATA_BASE    	RTL8367B_REG_TABLE_READ_DATA0

#define    RTL8367B_REG_DOT1X_CFG    		0x0a86
#define    RTL8367B_DOT1X_GVIDX_MASK    0x1F
#define    RTL8367B_DOT1X_PORT0_UNAUTHBH_MASK    0x3
#define    RTL8367B_DOT1X_CFG_REG    		RTL8367B_REG_DOT1X_CFG

#define    RTL8367B_REG_DOT1X_UNAUTH_ACT_W0    	0x0a84
#define    RTL8367B_DOT1X_UNAUTH_ACT_BASE    		RTL8367B_REG_DOT1X_UNAUTH_ACT_W0

#define    RTL8367B_REG_VLAN_PPB0_VALID   		 	0x0708
#define    RTL8367B_VLAN_PPB_VALID_BASE    			RTL8367B_REG_VLAN_PPB0_VALID

#define    RTL8367B_REG_VLAN_PPB0_CTRL0    			0x0709
#define    RTL8367B_VLAN_PPB_CTRL_BASE    			RTL8367B_REG_VLAN_PPB0_CTRL0

#define    RTL8367B_VLAN_PPB0_CTRL0_PORT0_INDEX_MASK    0x1F

#define    RTL8367B_REG_VLAN_PPB_PRIORITY_ITEM0_CTRL0    	0x0855
#define    RTL8367B_VLAN_PPB_PRIORITY_ITEM_BASE    			RTL8367B_REG_VLAN_PPB_PRIORITY_ITEM0_CTRL0
#define    RTL8367B_VLAN_PPB_PRIORITY_ITEM0_CTRL0_PORT0_PRIORITY_MASK    0x7

#define    RTL8367B_PORT0_MISC_CFG_VLAN_EGRESS_MODE_MASK    0x30
#define    RTL8367B_VLAN_CTRL_OFFSET    0

#define RTK_TOTAL_NUM_OF_WORD_FOR_1BIT_PORT_LIST    1


/****************************************************************/
/* Type Definition                                              */
/****************************************************************/

typedef rtk_uint32  rtk_vlan_t;        /* vlan id type */
typedef rtk_uint32  rtk_pri_t;         /* priority vlaue */
typedef rtk_uint32  rtk_fid_t;        /* filter id type */

typedef struct rtk_portmask_s
{
    rtk_uint32  bits[RTK_TOTAL_NUM_OF_WORD_FOR_1BIT_PORT_LIST];
} rtk_portmask_t;

enum DOT1X_UNAUTH_BEHAV
{
    DOT1X_UNAUTH_DROP = 0,
    DOT1X_UNAUTH_TRAP,
    DOT1X_UNAUTH_GVLAN,
    DOT1X_UNAUTH_END
};

enum RTL8367B_TABLE_ACCESS_OP
{
    TB_OP_READ = 0,
    TB_OP_WRITE
};

enum RTL8367B_TABLE_ACCESS_TARGET
{
    TB_TARGET_ACLRULE = 1,
    TB_TARGET_ACLACT,
    TB_TARGET_CVLAN,
    TB_TARGET_L2,
    TB_TARGET_IGMP_GROUP
};

typedef struct  VLANCONFIGSMI
{
#if 1//def _LITTLE_ENDIAN
	rtk_uint16	mbr:8;
	rtk_uint16  reserved:8;

	rtk_uint16	fid_msti:4;
	rtk_uint16  reserved2:12;
	
	rtk_uint16	vbpen:1;
	rtk_uint16	vbpri:3;
	rtk_uint16	envlanpol:1;
	rtk_uint16	meteridx:5;
	rtk_uint16	reserved3:6;

	rtk_uint16	evid:13;
	rtk_uint16  reserved4:3;
#else
	rtk_uint16  reserved:8;
	rtk_uint16	mbr:8;

	rtk_uint16  reserved2:12;
	rtk_uint16	fid_msti:4;
	
	rtk_uint16	reserved3:6;
	rtk_uint16	meteridx:5;
	rtk_uint16	envlanpol:1;
	rtk_uint16	vbpri:3;
	rtk_uint16	vbpen:1;

	rtk_uint16  reserved4:3;
	rtk_uint16	evid:13;
#endif
	
}rtl8367b_vlanconfigsmi;

typedef struct  VLANCONFIGUSER
{
    rtk_uint16 	evid;
	rtk_uint16 	mbr;
    rtk_uint16  fid_msti;
    rtk_uint16  envlanpol;
    rtk_uint16  meteridx;
    rtk_uint16  vbpen;
    rtk_uint16  vbpri;
}rtl8367b_vlanconfiguser;

typedef struct  VLANTABLE
{
#if 1//def _LITTLE_ENDIAN
	rtk_uint16 	mbr:8;
 	rtk_uint16 	untag:8;

 	rtk_uint16 	fid_msti:4;
 	rtk_uint16 	vbpen:1;
	rtk_uint16	vbpri:3;
	rtk_uint16	envlanpol:1;
	rtk_uint16	meteridx:5;
	rtk_uint16	ivl_svl:1;	
	rtk_uint16	reserved:1;	
#else
 	rtk_uint16 	untag:8;
	rtk_uint16 	mbr:8;

	rtk_uint16	reserved:1;
	rtk_uint16	ivl_svl:1;	
	rtk_uint16	meteridx:5;
	rtk_uint16	envlanpol:1;
	rtk_uint16	vbpri:3;
 	rtk_uint16 	vbpen:1;
 	rtk_uint16 	fid_msti:4;

#endif
}rtl8367b_vlan4kentrysmi;

typedef struct  USER_VLANTABLE{

	rtk_uint16 	vid;
	rtk_uint16 	mbr;
 	rtk_uint16 	untag;
    rtk_uint16  fid_msti;
    rtk_uint16  envlanpol;
    rtk_uint16  meteridx;
    rtk_uint16  vbpen;
    rtk_uint16  vbpri;
	rtk_uint16 	ivl_svl;

}rtl8367b_user_vlan4kentry;

typedef enum
{
    FRAME_TYPE_BOTH = 0,
    FRAME_TYPE_TAGGED_ONLY,
    FRAME_TYPE_UNTAGGED_ONLY,
    FRAME_TYPE_MAX_BOUND
} rtl8367b_accframetype;

typedef enum
{
    EG_TAG_MODE_ORI = 0,
    EG_TAG_MODE_KEEP,
    EG_TAG_MODE_PRI_TAG,
    EG_TAG_MODE_REAL_KEEP,    
    EG_TAG_MODE_END
} rtl8367b_egtagmode;

typedef enum
{
    PPVLAN_FRAME_TYPE_ETHERNET = 0,
    PPVLAN_FRAME_TYPE_LLC,
    PPVLAN_FRAME_TYPE_RFC1042,
    PPVLAN_FRAME_TYPE_END
} rtl8367b_provlan_frametype;

enum RTL8367B_STPST
{
	STPST_DISABLED = 0,
	STPST_BLOCKING,
	STPST_LEARNING,
	STPST_FORWARDING
};


typedef struct
{
    rtl8367b_provlan_frametype  frameType;
    rtk_uint32                      etherType;
} rtl8367b_protocolgdatacfg;

typedef struct
{
    rtk_uint32 valid;
    rtk_uint32 vlan_idx;
    rtk_uint32 priority;
} rtl8367b_protocolvlancfg;

#endif /*#ifndef _RTL8367B_ASICDRV_VLAN_H_*/

