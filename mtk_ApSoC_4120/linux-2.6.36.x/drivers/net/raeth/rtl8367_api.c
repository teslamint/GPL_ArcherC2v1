/*  Copyright(c) 2009-2013 Shenzhen TP-LINK Technologies Co.Ltd.
 *
 * file		rtl8367_api.c
 * brief		
 * details	
 *
 * author		Yuan Shang
 * version	
 * date		12Oct13
 *
 * history 	\arg	
 */
#include <linux/time.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/inetdevice.h>
#include "rtl8367_api.h"
#include "rtl8367_vlan.h"
#include "ra_ioctl.h"

/**************************************************************************************************/
/*                                           DEFINES                                              */
/**************************************************************************************************/
#define printf	printk
#define RTL8367_ERROR(fmt, args...) printk("\033[1m[ %s ] %03d: "fmt"\033[0m", __FUNCTION__, __LINE__, ##args)
#define RTL8367_DEBUG(fmt, args...) //printk("\033[4m[ %s ] %03d: "fmt"\033[0m", __FUNCTION__, __LINE__, ##args)

/* MDC_MDIO */
#define MDC_MDIO_DUMMY_ID           0x0
#define MDC_MDIO_CTRL0_REG          31
#define MDC_MDIO_START_REG          29
#define MDC_MDIO_CTRL1_REG          21
#define MDC_MDIO_ADDRESS_REG        23
#define MDC_MDIO_DATA_WRITE_REG     24
#define MDC_MDIO_DATA_READ_REG      25
#define MDC_MDIO_PREAMBLE_LEN       32
 
#define MDC_MDIO_START_OP          0xFFFF
#define MDC_MDIO_ADDR_OP           0x000E
#define MDC_MDIO_READ_OP           0x0001
#define MDC_MDIO_WRITE_OP          0x0003


/* EXT Interface */
#define RTL8367B_REG_DIGITAL_INTERFACE_SELECT	0x1305
#define RTL8367B_REG_DIGITAL_INTERFACE_SELECT_1 0x13c3

#define RTL8367B_REG_DIGITAL_INTERFACE1_FORCE	0x1311
#define RTL8367B_REG_DIGITAL_INTERFACE2_FORCE	0x13c4


#define    RTL8367B_SELECT_GMII_1_OFFSET    4


#define RTL8367B_REG_BYPASS_LINE_RATE 0x03f7


#define RTL8367_PORT0_STATUS_REG	0x1352

#define RTL8367B_REG_VLAN_MEMBER_CONFIGURATION0_CTRL0 0x0728
#define RTL8367B_REG_TABLE_WRITE_DATA0 0x0510
#define RTL8367B_REG_TABLE_ACCESS_ADDR 0x0501
#define RTL8367B_REG_TABLE_ACCESS_CTRL 0x0500
#define RTL8367B_REG_VLAN_PVID_CTRL0 0x0700
#define RTL8367B_PORT0_VIDX_MASK    0x1F

#define RTL8367B_REG_VLAN_PORTBASED_PRIORITY_CTRL0 0x0851

#define RTL8367B_REG_PORT0_MISC_CFG 0x000e
#define RTL8367B_REG_VLAN_CTRL 0x07a8


#define RTL8367B_VLAN_MEMBER_CONFIGURATION_BASE RTL8367B_REG_VLAN_MEMBER_CONFIGURATION0_CTRL0
#define RTL8367B_TABLE_ACCESS_WRDATA_BASE RTL8367B_REG_TABLE_WRITE_DATA0
#define RTL8367B_TABLE_ACCESS_ADDR_REG RTL8367B_REG_TABLE_ACCESS_ADDR
#define RTL8367B_TABLE_ACCESS_CTRL_REG RTL8367B_REG_TABLE_ACCESS_CTRL
#define RTL8367B_VLAN_PVID_CTRL_BASE RTL8367B_REG_VLAN_PVID_CTRL0
#define RTL8367B_VLAN_PORTBASED_PRIORITY_BASE RTL8367B_REG_VLAN_PORTBASED_PRIORITY_CTRL0

#define RTL8367B_PORT_MISC_CFG_BASE RTL8367B_REG_PORT0_MISC_CFG

#define RTL8367B_REG_MIB_COUNTER0 0x1000
#define RTL8367B_REG_MIB_COUNTER1 0x1001
#define RTL8367B_REG_MIB_COUNTER2 0x1002
#define RTL8367B_REG_MIB_COUNTER3 0x1003
#define RTL8367B_REG_MIB_ADDRESS  0x1004
#define RTL8367B_REG_MIB_CTRL0 0x1005
#define RTL8367B_MIB_CTRL_REG RTL8367B_REG_MIB_CTRL0


#define RTL8367B_CVIDXNO                    32
#define RTL8367B_CVIDXMAX                   (RTL8367B_CVIDXNO-1)


#define    RTL8367B_VLAN_PVID_CTRL_REG(port)    	(RTL8367B_VLAN_PVID_CTRL_BASE + (port >> 1))
#define    RTL8367B_PORT_VIDX_OFFSET(port)    		((port &1)<<3)
#define    RTL8367B_PORT_VIDX_MASK(port)    		(RTL8367B_PORT0_VIDX_MASK << RTL8367B_PORT_VIDX_OFFSET(port))

#define    RTL8367B_VLAN_PORTBASED_PRIORITY_BASE    		RTL8367B_REG_VLAN_PORTBASED_PRIORITY_CTRL0
#define    RTL8367B_VLAN_PORTBASED_PRIORITY_REG(port)    	(RTL8367B_VLAN_PORTBASED_PRIORITY_BASE + (port >> 2))
#define    RTL8367B_VLAN_PORTBASED_PRIORITY_OFFSET(port)    	((port & 0x3) << 2)
#define    RTL8367B_VLAN_PORTBASED_PRIORITY_MASK(port)    	(0x7 << RTL8367B_VLAN_PORTBASED_PRIORITY_OFFSET(port))

#define	 RTL8367B_TABLE_ACCESS_REG_DATA(op, target)	((op << 3) | target)

#define    RTL8367B_DOT1X_UNAUTH_ACT_OFFSET(port)		((port & 0x7) << 1)
#define    RTL8367B_DOT1X_UNAUTH_ACT_MASK(port)		(RTL8367B_DOT1X_PORT0_UNAUTHBH_MASK << RTL8367B_DOT1X_UNAUTH_ACT_OFFSET(port))

#define    RTL8367B_VLAN_PPB_VALID_REG(item)    			(RTL8367B_VLAN_PPB_VALID_BASE + (item << 3))
#define    RTL8367B_VLAN_PPB_CTRL_REG(item, port)   		(RTL8367B_VLAN_PPB_CTRL_BASE + (item << 3) + (port / 3) )
#define    RTL8367B_VLAN_PPB_CTRL_OFFSET(port)    		((port % 3) * 5)
#define    RTL8367B_VLAN_PPB_CTRL_MASK(port)    			(RTL8367B_VLAN_PPB0_CTRL0_PORT0_INDEX_MASK << RTL8367B_VLAN_PPB_CTRL_OFFSET(port))
#define    RTL8367B_VLAN_PPB_PRIORITY_ITEM_REG(port, item)    	(RTL8367B_VLAN_PPB_PRIORITY_ITEM_BASE + (item << 2)+ (port>>2))
#define    RTL8367B_VLAN_PPB_PRIORITY_ITEM_OFFSET(port)    	((port & 0x3) <<2)
#define    RTL8367B_VLAN_PPB_PRIORITY_ITEM_MASK(port)    	(RTL8367B_VLAN_PPB_PRIORITY_ITEM0_CTRL0_PORT0_PRIORITY_MASK << RTL8367B_VLAN_PPB_PRIORITY_ITEM_OFFSET(port))

#define    RTL8367B_PORT_MISC_CFG_REG(port)    			(RTL8367B_PORT_MISC_CFG_BASE + (port << 5))
#define    RTL8367B_VLAN_EGRESS_MDOE_MASK    			RTL8367B_PORT0_MISC_CFG_VLAN_EGRESS_MODE_MASK

#define    ENABLE_PORT_6
#define    ENABLE_PORT_7

/**************************************************************************************************/
/*                                           TYPES                                                */
/**************************************************************************************************/
typedef enum rtk_mode_ext_e
{
    MODE_EXT_DISABLE = 0,
    MODE_EXT_RGMII,
    MODE_EXT_MII_MAC,
    MODE_EXT_MII_PHY,
    MODE_EXT_TMII_MAC,
    MODE_EXT_TMII_PHY,
    MODE_EXT_GMII,
    MODE_EXT_RMII_MAC,
    MODE_EXT_RMII_PHY,
    MODE_EXT_RGMII_33V,
    MODE_EXT_END
} rtk_mode_ext_t;

typedef enum rtk_ext_port_e
{
    EXT_PORT_0 = 0,
    EXT_PORT_1,
    EXT_PORT_2,
    EXT_PORT_END
}rtk_ext_port_t;

typedef struct  rtl8367b_port_ability_s{
#if 0//def _LITTLE_ENDIAN
    u16 speed:2;
    u16 duplex:1;
    u16 reserve1:1;
    u16 link:1;
    u16 rxpause:1;
    u16 txpause:1;
    u16 nway:1;
    u16 mstmode:1;
    u16 mstfault:1;
    u16 reserve2:2;
    u16 forcemode:1;
    u16 reserve3:3;
#else
    u16 reserve3:3;
    u16 forcemode:1;
    u16 reserve2:2;
    u16 mstfault:1;
    u16 mstmode:1;
    u16 nway:1;
    u16 txpause:1;
    u16 rxpause:1;
    u16 link:1;
    u16 reserve1:1;
    u16 duplex:1;
    u16 speed:2;
#endif
}rtl8367b_port_ability_t;

typedef enum RTL8367B_MIBCOUNTER_E{

    /* RX */
	ifInOctets = 0,

	dot3StatsFCSErrors,
	dot3StatsSymbolErrors,
	dot3InPauseFrames,
	dot3ControlInUnknownOpcodes,	
	
	etherStatsFragments,
	etherStatsJabbers,
	ifInUcastPkts,
	etherStatsDropEvents,

    ifInMulticastPkts,
    ifInBroadcastPkts,
    inMldChecksumError,
    inIgmpChecksumError,
    inMldSpecificQuery,
    inMldGeneralQuery,
    inIgmpSpecificQuery,
    inIgmpGeneralQuery,
    inMldLeaves,
    inIgmpLeaves,

    /* TX/RX */
	etherStatsOctets,

	etherStatsUnderSizePkts,
	etherOversizeStats,
	etherStatsPkts64Octets,
	etherStatsPkts65to127Octets,
	etherStatsPkts128to255Octets,
	etherStatsPkts256to511Octets,
	etherStatsPkts512to1023Octets,
	etherStatsPkts1024to1518Octets,

    /* TX */
	ifOutOctets,

	dot3StatsSingleCollisionFrames,
	dot3StatMultipleCollisionFrames,
	dot3sDeferredTransmissions,
	dot3StatsLateCollisions,
	etherStatsCollisions,
	dot3StatsExcessiveCollisions,
	dot3OutPauseFrames,
    ifOutDiscards,

    /* ALE */
	dot1dTpPortInDiscards,
	ifOutUcastPkts,
	ifOutMulticastPkts,
	ifOutBroadcastPkts,
	outOampduPkts,
	inOampduPkts,

    inIgmpJoinsSuccess,
    inIgmpJoinsFail,
    inMldJoinsSuccess,
    inMldJoinsFail,
    inReportSuppressionDrop,
    inLeaveSuppressionDrop,
    outIgmpReports,
    outIgmpLeaves,
    outIgmpGeneralQuery,
    outIgmpSpecificQuery,
    outMldReports,
    outMldLeaves,
    outMldGeneralQuery,
    outMldSpecificQuery,
    inKnownMulticastPkts,

	/*Device only */	
	dot1dTpLearnedEntryDiscards,
	RTL8367B_MIBS_NUMBER,
	
}RTL8367B_MIBCOUNTER;

/**************************************************************************************************/
/*                                           EXTERN_PROTOTYPES                                    */
/**************************************************************************************************/
extern int mii_mgr_read(u32 phy_addr, u32 phy_register, u32 *read_data);
extern int mii_mgr_write(u32 phy_addr, u32 phy_register, u32 write_data);

/**************************************************************************************************/
/*                                           LOCAL_PROTOTYPES                                     */
/**************************************************************************************************/
/* common settings  */
u32 rtl8367b_setAsicRegBit(u32 reg, u32 bit, u32 value);
u32 rtl8367b_setAsicRegBits(u32 reg, u32 bits, u32 value);
ret_t rtl8367b_setAsicReg(rtk_uint32 reg, rtk_uint32 value);
ret_t rtl8367b_setAsicReg(rtk_uint32 reg, rtk_uint32 value);
ret_t rtl8367b_setAsicPHYReg( rtk_uint32 phyNo, rtk_uint32 phyAddr, rtk_uint32 value);
ret_t rtl8367b_getAsicPHYReg( rtk_uint32 phyNo, rtk_uint32 phyAddr, rtk_uint32 *value);
/* test mode settings  */
rtk_api_ret_t rtk_port_phyTestModeAll_set(rtk_port_t port, rtk_port_phy_test_mode_t mode);
rtk_api_ret_t rtk_port_phyTestModeAll_get(rtk_port_t port, rtk_port_phy_test_mode_t *pMode);
/* swicth init settings  */
static rtk_api_ret_t _rtk_switch_init_setreg(rtk_uint32 reg, rtk_uint32 data);
/* vlan settings  */
void _rtl8367b_Vlan4kStUser2Smi(rtl8367b_user_vlan4kentry *pUserVlan4kEntry, rtl8367b_vlan4kentrysmi *pSmiVlan4kEntry);
void _rtl8367b_Vlan4kStSmi2User(rtl8367b_vlan4kentrysmi *pSmiVlan4kEntry, rtl8367b_user_vlan4kentry *pUserVlan4kEntry);
void _rtl8367b_VlanMCStSmi2User(rtl8367b_vlanconfigsmi *pSmiVlanCfg, rtl8367b_vlanconfiguser *pVlanCg);
void _rtl8367b_VlanMCStUser2Smi(rtl8367b_vlanconfiguser *pVlanCg, rtl8367b_vlanconfigsmi *pSmiVlanCfg);
ret_t rtl8367b_setAsicVlan4kEntry(rtl8367b_user_vlan4kentry *pVlan4kEntry );
ret_t rtl8367b_getAsicVlan4kEntry(rtl8367b_user_vlan4kentry *pVlan4kEntry );
ret_t rtl8367b_getAsicVlanMemberConfig(rtk_uint32 index, rtl8367b_vlanconfiguser *pVlanCg);
ret_t rtl8367b_setAsicVlanMemberConfig(rtk_uint32 index, rtl8367b_vlanconfiguser *pVlanCg);
ret_t rtl8367b_setAsicVlanPortBasedVID(rtk_uint32 port, rtk_uint32 index, rtk_uint32 pri);
ret_t rtl8367b_getAsicVlanPortBasedVID(rtk_uint32 port, rtk_uint32 *pIndex, rtk_uint32 *pPri);
ret_t rtl8367b_getAsicRegBit(rtk_uint32 reg, rtk_uint32 bit, rtk_uint32 *pValue);
ret_t rtl8367b_getAsicRegBits(rtk_uint32 reg, rtk_uint32 bits, rtk_uint32 *pValue);
ret_t rtl8367b_getAsic1xGuestVidx(rtk_uint32 *pIndex);
ret_t rtl8367b_getAsic1xProcConfig(rtk_uint32 port, rtk_uint32* pProc);
ret_t rtl8367b_getAsicVlanPortAndProtocolBased(rtk_uint32 port, rtk_uint32 index, rtl8367b_protocolvlancfg *pPpbCfg);
rtk_api_ret_t rtk_vlan_set(rtk_vlan_t vid, rtk_portmask_t mbrmsk, rtk_portmask_t untagmsk, rtk_fid_t fid);
rtk_api_ret_t rtk_vlan_portPvid_set(rtk_port_t port, rtk_vlan_t pvid, rtk_pri_t priority);
ret_t rtl8367b_setAsicVlanEgressTagMode(rtk_uint32 port, rtl8367b_egtagmode tagMode);
ret_t rtl8367b_setAsicVlanFilter(rtk_uint32 enabled);
void externalInterfaceDelay();
void IsSwitchVlanTableBusy();
void vlanDump();
rtk_api_ret_t setVlanRtl8367();
rtk_api_ret_t setVlanInner();
/* igmp settings  */
ret_t rtl8367b_setAsicIGMPStaticRouterPort(rtk_uint32 pmsk);
rtk_api_ret_t rtk_igmp_static_router_port_set(rtk_portmask_t portmask);
/*  lookup table settings */
ret_t rtl8367b_setAsicLutIpMulticastLookup(rtk_uint32 enabled);
ret_t rtl8367b_setAsicLutIpLookupMethod(rtk_uint32 type);
void _rtl8367b_fdbStUser2Smi( rtl8367b_luttb *pLutSt, rtl8367b_fdbtb *pFdbSmi);
void _rtl8367b_fdbStSmi2User( rtl8367b_luttb *pLutSt, rtl8367b_fdbtb *pFdbSmi);
ret_t rtl8367b_getAsicL2LookupTb(rtk_uint32 method, rtl8367b_luttb *pL2Table);
ret_t rtl8367b_setAsicL2LookupTb(rtl8367b_luttb *pL2Table);
rtk_api_ret_t rtk_l2_addr_get(rtk_mac_t *pMac, rtk_l2_ucastAddr_t *pL2_data);
rtk_api_ret_t rtk_l2_ipMcastAddr_get(ipaddr_t sip, ipaddr_t dip, rtk_portmask_t *pPortmask);
rtk_api_ret_t rtk_l2_ipMcastAddr_add(ipaddr_t sip, ipaddr_t dip, rtk_portmask_t portmask);
rtk_api_ret_t rtk_l2_ipMcastAddr_del(ipaddr_t sip, ipaddr_t dip);
rtk_api_ret_t rtk_l2_ipMcastAddrLookup_set(rtk_l2_lookup_type_t type);
rtk_api_ret_t ipMcastRuleSet(struct rtl8367IpMcastRule ipMcastRule, ipMcastRuleType ruleType);
static void reg_read(int offset, int *value);
static void reg_write(int offset, int value);
rtk_api_ret_t mtk_l2_ipMcastAddr_add(unsigned int ip_addr, unsigned char portmsk);
rtk_api_ret_t mtk_l2_ipMcastAddr_del(unsigned int ip_addr);
rtk_api_ret_t mtk_l2_ipMcastAddr_get(unsigned int ip_addr, unsigned char *portMsk);
rtk_api_ret_t mtk_l2_addr_get(unsigned char *pMac, unsigned char *portMsk);
rtk_api_ret_t MT7620IpMcastRuleSet(struct rtl8367IpMcastRule ipMcastRule, ipMcastRuleType ruleType);

/**************************************************************************************************/
/*                                           VARIABLES                                            */
/**************************************************************************************************/
rtk_uint16	(*init_para)[2];
rtk_uint16      init_size;

rtk_uint16 ChipData30[][2]= {
/*Code of Func*/
{0x1B03, 0x0876}, {0x1200, 0x7FC4}, {0x0301, 0x0026}, {0x1722, 0x0E14},
{0x205F, 0x0002}, {0x2059, 0x1A00}, {0x205F, 0x0000}, {0x207F, 0x0002},
{0x2077, 0x0000}, {0x2078, 0x0000}, {0x2079, 0x0000}, {0x207A, 0x0000},
{0x207B, 0x0000}, {0x207F, 0x0000}, {0x205F, 0x0002}, {0x2053, 0x0000},
{0x2054, 0x0000}, {0x2055, 0x0000}, {0x2056, 0x0000}, {0x2057, 0x0000},
{0x205F, 0x0000}, {0x12A4, 0x110A}, {0x12A6, 0x150A}, {0x13F1, 0x0013},
{0x13F4, 0x0010}, {0x13F5, 0x0000}, {0x0018, 0x0F00}, {0x0038, 0x0F00},
{0x0058, 0x0F00}, {0x0078, 0x0F00}, {0x0098, 0x0F00}, {0x12B6, 0x0C02},
{0x12B7, 0x030F}, {0x12B8, 0x11FF}, {0x12BC, 0x0004}, {0x1362, 0x0115},
{0x1363, 0x0002}, {0x1363, 0x0000}, {0x133F, 0x0030}, {0x133E, 0x000E},
{0x221F, 0x0007}, {0x221E, 0x002D}, {0x2218, 0xF030}, {0x221F, 0x0007},
{0x221E, 0x0023}, {0x2216, 0x0005}, {0x2215, 0x00B9}, {0x2219, 0x0044},
{0x2215, 0x00BA}, {0x2219, 0x0020}, {0x2215, 0x00BB}, {0x2219, 0x00C1},
{0x2215, 0x0148}, {0x2219, 0x0096}, {0x2215, 0x016E}, {0x2219, 0x0026},
{0x2216, 0x0000}, {0x2216, 0x0000}, {0x221E, 0x002D}, {0x2218, 0xF010},
{0x221F, 0x0007}, {0x221E, 0x0020}, {0x2215, 0x0D00}, {0x221F, 0x0000},
{0x221F, 0x0000}, {0x2217, 0x2160}, {0x221F, 0x0001}, {0x2210, 0xF25E},
{0x221F, 0x0007}, {0x221E, 0x0042}, {0x2215, 0x0F00}, {0x2215, 0x0F00},
{0x2216, 0x7408}, {0x2215, 0x0E00}, {0x2215, 0x0F00}, {0x2215, 0x0F01},
{0x2216, 0x4000}, {0x2215, 0x0E01}, {0x2215, 0x0F01}, {0x2215, 0x0F02},
{0x2216, 0x9400}, {0x2215, 0x0E02}, {0x2215, 0x0F02}, {0x2215, 0x0F03},
{0x2216, 0x7408}, {0x2215, 0x0E03}, {0x2215, 0x0F03}, {0x2215, 0x0F04},
{0x2216, 0x4008}, {0x2215, 0x0E04}, {0x2215, 0x0F04}, {0x2215, 0x0F05},
{0x2216, 0x9400}, {0x2215, 0x0E05}, {0x2215, 0x0F05}, {0x2215, 0x0F06},
{0x2216, 0x0803}, {0x2215, 0x0E06}, {0x2215, 0x0F06}, {0x2215, 0x0D00},
{0x2215, 0x0100}, {0x221F, 0x0001}, {0x2210, 0xF05E}, {0x221F, 0x0000},
{0x2217, 0x2100}, {0x221F, 0x0000}, {0x220D, 0x0003}, {0x220E, 0x0015},
{0x220D, 0x4003}, {0x220E, 0x0006}, {0x221F, 0x0000}, {0x2200, 0x1340},
{0x133F, 0x0010}, {0x12A0, 0x0058}, {0x12A1, 0x0058}, {0x133E, 0x000E},
{0x133F, 0x0030}, {0x221F, 0x0000}, {0x2210, 0x0166}, {0x221F, 0x0000},
{0x133E, 0x000E}, {0x133F, 0x0010}, {0x133F, 0x0030}, {0x133E, 0x000E},
{0x221F, 0x0005}, {0x2205, 0xFFF6}, {0x2206, 0x0080}, {0x2205, 0x8B6E},
{0x2206, 0x0000}, {0x220F, 0x0100}, {0x2205, 0x8000}, {0x2206, 0x0280},
{0x2206, 0x28F7}, {0x2206, 0x00E0}, {0x2206, 0xFFF7}, {0x2206, 0xA080},
{0x2206, 0x02AE}, {0x2206, 0xF602}, {0x2206, 0x0153}, {0x2206, 0x0201},
{0x2206, 0x6602}, {0x2206, 0x80B9}, {0x2206, 0xE08B}, {0x2206, 0x8CE1},
{0x2206, 0x8B8D}, {0x2206, 0x1E01}, {0x2206, 0xE18B}, {0x2206, 0x8E1E},
{0x2206, 0x01A0}, {0x2206, 0x00E7}, {0x2206, 0xAEDB}, {0x2206, 0xEEE0},
{0x2206, 0x120E}, {0x2206, 0xEEE0}, {0x2206, 0x1300}, {0x2206, 0xEEE0},
{0x2206, 0x2001}, {0x2206, 0xEEE0}, {0x2206, 0x2166}, {0x2206, 0xEEE0},
{0x2206, 0xC463}, {0x2206, 0xEEE0}, {0x2206, 0xC5E8}, {0x2206, 0xEEE0},
{0x2206, 0xC699}, {0x2206, 0xEEE0}, {0x2206, 0xC7C2}, {0x2206, 0xEEE0},
{0x2206, 0xC801}, {0x2206, 0xEEE0}, {0x2206, 0xC913}, {0x2206, 0xEEE0},
{0x2206, 0xCA30}, {0x2206, 0xEEE0}, {0x2206, 0xCB3E}, {0x2206, 0xEEE0},
{0x2206, 0xDCE1}, {0x2206, 0xEEE0}, {0x2206, 0xDD00}, {0x2206, 0xEEE2},
{0x2206, 0x0001}, {0x2206, 0xEEE2}, {0x2206, 0x0100}, {0x2206, 0xEEE4},
{0x2206, 0x8860}, {0x2206, 0xEEE4}, {0x2206, 0x8902}, {0x2206, 0xEEE4},
{0x2206, 0x8C00}, {0x2206, 0xEEE4}, {0x2206, 0x8D30}, {0x2206, 0xEEEA},
{0x2206, 0x1480}, {0x2206, 0xEEEA}, {0x2206, 0x1503}, {0x2206, 0xEEEA},
{0x2206, 0xC600}, {0x2206, 0xEEEA}, {0x2206, 0xC706}, {0x2206, 0xEE85},
{0x2206, 0xEE00}, {0x2206, 0xEE85}, {0x2206, 0xEF00}, {0x2206, 0xEE8B},
{0x2206, 0x6750}, {0x2206, 0xEE8B}, {0x2206, 0x6632}, {0x2206, 0xEE8A},
{0x2206, 0xD448}, {0x2206, 0xEE8A}, {0x2206, 0xD548}, {0x2206, 0xEE8A},
{0x2206, 0xD649}, {0x2206, 0xEE8A}, {0x2206, 0xD7F8}, {0x2206, 0xEE8B},
{0x2206, 0x85E2}, {0x2206, 0xEE8B}, {0x2206, 0x8700}, {0x2206, 0xEEFF},
{0x2206, 0xF600}, {0x2206, 0xEEFF}, {0x2206, 0xF7FC}, {0x2206, 0x04F8},
{0x2206, 0xE08B}, {0x2206, 0x8EAD}, {0x2206, 0x2023}, {0x2206, 0xF620},
{0x2206, 0xE48B}, {0x2206, 0x8E02}, {0x2206, 0x2877}, {0x2206, 0x0225},
{0x2206, 0xC702}, {0x2206, 0x26A1}, {0x2206, 0x0281}, {0x2206, 0xB302},
{0x2206, 0x8496}, {0x2206, 0x0202}, {0x2206, 0xA102}, {0x2206, 0x27F1},
{0x2206, 0x0228}, {0x2206, 0xF902}, {0x2206, 0x2AA0}, {0x2206, 0x0282},
{0x2206, 0xB8E0}, {0x2206, 0x8B8E}, {0x2206, 0xAD21}, {0x2206, 0x08F6},
{0x2206, 0x21E4}, {0x2206, 0x8B8E}, {0x2206, 0x0202}, {0x2206, 0x80E0},
{0x2206, 0x8B8E}, {0x2206, 0xAD22}, {0x2206, 0x05F6}, {0x2206, 0x22E4},
{0x2206, 0x8B8E}, {0x2206, 0xE08B}, {0x2206, 0x8EAD}, {0x2206, 0x2305},
{0x2206, 0xF623}, {0x2206, 0xE48B}, {0x2206, 0x8EE0}, {0x2206, 0x8B8E},
{0x2206, 0xAD24}, {0x2206, 0x08F6}, {0x2206, 0x24E4}, {0x2206, 0x8B8E},
{0x2206, 0x0227}, {0x2206, 0x6AE0}, {0x2206, 0x8B8E}, {0x2206, 0xAD25},
{0x2206, 0x05F6}, {0x2206, 0x25E4}, {0x2206, 0x8B8E}, {0x2206, 0xE08B},
{0x2206, 0x8EAD}, {0x2206, 0x260B}, {0x2206, 0xF626}, {0x2206, 0xE48B},
{0x2206, 0x8E02}, {0x2206, 0x830D}, {0x2206, 0x021D}, {0x2206, 0x6BE0},
{0x2206, 0x8B8E}, {0x2206, 0xAD27}, {0x2206, 0x05F6}, {0x2206, 0x27E4},
{0x2206, 0x8B8E}, {0x2206, 0x0281}, {0x2206, 0x4402}, {0x2206, 0x045C},
{0x2206, 0xFC04}, {0x2206, 0xF8E0}, {0x2206, 0x8B83}, {0x2206, 0xAD23},
{0x2206, 0x30E0}, {0x2206, 0xE022}, {0x2206, 0xE1E0}, {0x2206, 0x2359},
{0x2206, 0x02E0}, {0x2206, 0x85EF}, {0x2206, 0xE585}, {0x2206, 0xEFAC},
{0x2206, 0x2907}, {0x2206, 0x1F01}, {0x2206, 0x9E51}, {0x2206, 0xAD29},
{0x2206, 0x20E0}, {0x2206, 0x8B83}, {0x2206, 0xAD21}, {0x2206, 0x06E1},
{0x2206, 0x8B84}, {0x2206, 0xAD28}, {0x2206, 0x42E0}, {0x2206, 0x8B85},
{0x2206, 0xAD21}, {0x2206, 0x06E1}, {0x2206, 0x8B84}, {0x2206, 0xAD29},
{0x2206, 0x36BF}, {0x2206, 0x34BF}, {0x2206, 0x022C}, {0x2206, 0x31AE},
{0x2206, 0x2EE0}, {0x2206, 0x8B83}, {0x2206, 0xAD21}, {0x2206, 0x10E0},
{0x2206, 0x8B84}, {0x2206, 0xF620}, {0x2206, 0xE48B}, {0x2206, 0x84EE},
{0x2206, 0x8ADA}, {0x2206, 0x00EE}, {0x2206, 0x8ADB}, {0x2206, 0x00E0},
{0x2206, 0x8B85}, {0x2206, 0xAD21}, {0x2206, 0x0CE0}, {0x2206, 0x8B84},
{0x2206, 0xF621}, {0x2206, 0xE48B}, {0x2206, 0x84EE}, {0x2206, 0x8B72},
{0x2206, 0xFFBF}, {0x2206, 0x34C2}, {0x2206, 0x022C}, {0x2206, 0x31FC},
{0x2206, 0x04F8}, {0x2206, 0xFAEF}, {0x2206, 0x69E0}, {0x2206, 0x8B85},
{0x2206, 0xAD21}, {0x2206, 0x42E0}, {0x2206, 0xE022}, {0x2206, 0xE1E0},
{0x2206, 0x2358}, {0x2206, 0xC059}, {0x2206, 0x021E}, {0x2206, 0x01E1},
{0x2206, 0x8B72}, {0x2206, 0x1F10}, {0x2206, 0x9E2F}, {0x2206, 0xE48B},
{0x2206, 0x72AD}, {0x2206, 0x2123}, {0x2206, 0xE18B}, {0x2206, 0x84F7},
{0x2206, 0x29E5}, {0x2206, 0x8B84}, {0x2206, 0xAC27}, {0x2206, 0x10AC},
{0x2206, 0x2605}, {0x2206, 0x0205}, {0x2206, 0x23AE}, {0x2206, 0x1602},
{0x2206, 0x0535}, {0x2206, 0x0282}, {0x2206, 0x30AE}, {0x2206, 0x0E02},
{0x2206, 0x056A}, {0x2206, 0x0282}, {0x2206, 0x75AE}, {0x2206, 0x0602},
{0x2206, 0x04DC}, {0x2206, 0x0282}, {0x2206, 0x04EF}, {0x2206, 0x96FE},
{0x2206, 0xFC04}, {0x2206, 0xF8F9}, {0x2206, 0xE08B}, {0x2206, 0x87AD},
{0x2206, 0x2321}, {0x2206, 0xE0EA}, {0x2206, 0x14E1}, {0x2206, 0xEA15},
{0x2206, 0xAD26}, {0x2206, 0x18F6}, {0x2206, 0x27E4}, {0x2206, 0xEA14},
{0x2206, 0xE5EA}, {0x2206, 0x15F6}, {0x2206, 0x26E4}, {0x2206, 0xEA14},
{0x2206, 0xE5EA}, {0x2206, 0x15F7}, {0x2206, 0x27E4}, {0x2206, 0xEA14},
{0x2206, 0xE5EA}, {0x2206, 0x15FD}, {0x2206, 0xFC04}, {0x2206, 0xF8F9},
{0x2206, 0xE08B}, {0x2206, 0x87AD}, {0x2206, 0x233A}, {0x2206, 0xAD22},
{0x2206, 0x37E0}, {0x2206, 0xE020}, {0x2206, 0xE1E0}, {0x2206, 0x21AC},
{0x2206, 0x212E}, {0x2206, 0xE0EA}, {0x2206, 0x14E1}, {0x2206, 0xEA15},
{0x2206, 0xF627}, {0x2206, 0xE4EA}, {0x2206, 0x14E5}, {0x2206, 0xEA15},
{0x2206, 0xE2EA}, {0x2206, 0x12E3}, {0x2206, 0xEA13}, {0x2206, 0x5A8F},
{0x2206, 0x6A20}, {0x2206, 0xE6EA}, {0x2206, 0x12E7}, {0x2206, 0xEA13},
{0x2206, 0xF726}, {0x2206, 0xE4EA}, {0x2206, 0x14E5}, {0x2206, 0xEA15},
{0x2206, 0xF727}, {0x2206, 0xE4EA}, {0x2206, 0x14E5}, {0x2206, 0xEA15},
{0x2206, 0xFDFC}, {0x2206, 0x04F8}, {0x2206, 0xF9E0}, {0x2206, 0x8B87},
{0x2206, 0xAD23}, {0x2206, 0x38AD}, {0x2206, 0x2135}, {0x2206, 0xE0E0},
{0x2206, 0x20E1}, {0x2206, 0xE021}, {0x2206, 0xAC21}, {0x2206, 0x2CE0},
{0x2206, 0xEA14}, {0x2206, 0xE1EA}, {0x2206, 0x15F6}, {0x2206, 0x27E4},
{0x2206, 0xEA14}, {0x2206, 0xE5EA}, {0x2206, 0x15E2}, {0x2206, 0xEA12},
{0x2206, 0xE3EA}, {0x2206, 0x135A}, {0x2206, 0x8FE6}, {0x2206, 0xEA12},
{0x2206, 0xE7EA}, {0x2206, 0x13F7}, {0x2206, 0x26E4}, {0x2206, 0xEA14},
{0x2206, 0xE5EA}, {0x2206, 0x15F7}, {0x2206, 0x27E4}, {0x2206, 0xEA14},
{0x2206, 0xE5EA}, {0x2206, 0x15FD}, {0x2206, 0xFC04}, {0x2206, 0xF8FA},
{0x2206, 0xEF69}, {0x2206, 0xE08B}, {0x2206, 0x86AD}, {0x2206, 0x2146},
{0x2206, 0xE0E0}, {0x2206, 0x22E1}, {0x2206, 0xE023}, {0x2206, 0x58C0},
{0x2206, 0x5902}, {0x2206, 0x1E01}, {0x2206, 0xE18B}, {0x2206, 0x651F},
{0x2206, 0x109E}, {0x2206, 0x33E4}, {0x2206, 0x8B65}, {0x2206, 0xAD21},
{0x2206, 0x22AD}, {0x2206, 0x272A}, {0x2206, 0xD400}, {0x2206, 0x01BF},
{0x2206, 0x34F2}, {0x2206, 0x022C}, {0x2206, 0xA2BF}, {0x2206, 0x34F5},
{0x2206, 0x022C}, {0x2206, 0xE0E0}, {0x2206, 0x8B67}, {0x2206, 0x1B10},
{0x2206, 0xAA14}, {0x2206, 0xE18B}, {0x2206, 0x660D}, {0x2206, 0x1459},
{0x2206, 0x0FAE}, {0x2206, 0x05E1}, {0x2206, 0x8B66}, {0x2206, 0x590F},
{0x2206, 0xBF85}, {0x2206, 0x6102}, {0x2206, 0x2CA2}, {0x2206, 0xEF96},
{0x2206, 0xFEFC}, {0x2206, 0x04F8}, {0x2206, 0xF9FA}, {0x2206, 0xFBEF},
{0x2206, 0x79E2}, {0x2206, 0x8AD2}, {0x2206, 0xAC19}, {0x2206, 0x2DE0},
{0x2206, 0xE036}, {0x2206, 0xE1E0}, {0x2206, 0x37EF}, {0x2206, 0x311F},
{0x2206, 0x325B}, {0x2206, 0x019E}, {0x2206, 0x1F7A}, {0x2206, 0x0159},
{0x2206, 0x019F}, {0x2206, 0x0ABF}, {0x2206, 0x348E}, {0x2206, 0x022C},
{0x2206, 0x31F6}, {0x2206, 0x06AE}, {0x2206, 0x0FF6}, {0x2206, 0x0302},
{0x2206, 0x0470}, {0x2206, 0xF703}, {0x2206, 0xF706}, {0x2206, 0xBF34},
{0x2206, 0x9302}, {0x2206, 0x2C31}, {0x2206, 0xAC1A}, {0x2206, 0x25E0},
{0x2206, 0xE022}, {0x2206, 0xE1E0}, {0x2206, 0x23EF}, {0x2206, 0x300D},
{0x2206, 0x311F}, {0x2206, 0x325B}, {0x2206, 0x029E}, {0x2206, 0x157A},
{0x2206, 0x0258}, {0x2206, 0xC4A0}, {0x2206, 0x0408}, {0x2206, 0xBF34},
{0x2206, 0x9E02}, {0x2206, 0x2C31}, {0x2206, 0xAE06}, {0x2206, 0xBF34},
{0x2206, 0x9C02}, {0x2206, 0x2C31}, {0x2206, 0xAC1B}, {0x2206, 0x4AE0},
{0x2206, 0xE012}, {0x2206, 0xE1E0}, {0x2206, 0x13EF}, {0x2206, 0x300D},
{0x2206, 0x331F}, {0x2206, 0x325B}, {0x2206, 0x1C9E}, {0x2206, 0x3AEF},
{0x2206, 0x325B}, {0x2206, 0x1C9F}, {0x2206, 0x09BF}, {0x2206, 0x3498},
{0x2206, 0x022C}, {0x2206, 0x3102}, {0x2206, 0x83C5}, {0x2206, 0x5A03},
{0x2206, 0x0D03}, {0x2206, 0x581C}, {0x2206, 0x1E20}, {0x2206, 0x0207},
{0x2206, 0xA0A0}, {0x2206, 0x000E}, {0x2206, 0x0284}, {0x2206, 0x17AD},
{0x2206, 0x1817}, {0x2206, 0xBF34}, {0x2206, 0x9A02}, {0x2206, 0x2C31},
{0x2206, 0xAE0F}, {0x2206, 0xBF34}, {0x2206, 0xC802}, {0x2206, 0x2C31},
{0x2206, 0xBF34}, {0x2206, 0xC502}, {0x2206, 0x2C31}, {0x2206, 0x0284},
{0x2206, 0x52E6}, {0x2206, 0x8AD2}, {0x2206, 0xEF97}, {0x2206, 0xFFFE},
{0x2206, 0xFDFC}, {0x2206, 0x04F8}, {0x2206, 0xBF34}, {0x2206, 0xDA02},
{0x2206, 0x2CE0}, {0x2206, 0xE58A}, {0x2206, 0xD3BF}, {0x2206, 0x34D4},
{0x2206, 0x022C}, {0x2206, 0xE00C}, {0x2206, 0x1159}, {0x2206, 0x02E0},
{0x2206, 0x8AD3}, {0x2206, 0x1E01}, {0x2206, 0xE48A}, {0x2206, 0xD3D1},
{0x2206, 0x00BF}, {0x2206, 0x34DA}, {0x2206, 0x022C}, {0x2206, 0xA2D1},
{0x2206, 0x01BF}, {0x2206, 0x34D4}, {0x2206, 0x022C}, {0x2206, 0xA2BF},
{0x2206, 0x34CB}, {0x2206, 0x022C}, {0x2206, 0xE0E5}, {0x2206, 0x8ACE},
{0x2206, 0xBF85}, {0x2206, 0x6702}, {0x2206, 0x2CE0}, {0x2206, 0xE58A},
{0x2206, 0xCFBF}, {0x2206, 0x8564}, {0x2206, 0x022C}, {0x2206, 0xE0E5},
{0x2206, 0x8AD0}, {0x2206, 0xBF85}, {0x2206, 0x6A02}, {0x2206, 0x2CE0},
{0x2206, 0xE58A}, {0x2206, 0xD1FC}, {0x2206, 0x04F8}, {0x2206, 0xE18A},
{0x2206, 0xD1BF}, {0x2206, 0x856A}, {0x2206, 0x022C}, {0x2206, 0xA2E1},
{0x2206, 0x8AD0}, {0x2206, 0xBF85}, {0x2206, 0x6402}, {0x2206, 0x2CA2},
{0x2206, 0xE18A}, {0x2206, 0xCFBF}, {0x2206, 0x8567}, {0x2206, 0x022C},
{0x2206, 0xA2E1}, {0x2206, 0x8ACE}, {0x2206, 0xBF34}, {0x2206, 0xCB02},
{0x2206, 0x2CA2}, {0x2206, 0xE18A}, {0x2206, 0xD3BF}, {0x2206, 0x34DA},
{0x2206, 0x022C}, {0x2206, 0xA2E1}, {0x2206, 0x8AD3}, {0x2206, 0x0D11},
{0x2206, 0xBF34}, {0x2206, 0xD402}, {0x2206, 0x2CA2}, {0x2206, 0xFC04},
{0x2206, 0xF9A0}, {0x2206, 0x0405}, {0x2206, 0xE38A}, {0x2206, 0xD4AE},
{0x2206, 0x13A0}, {0x2206, 0x0805}, {0x2206, 0xE38A}, {0x2206, 0xD5AE},
{0x2206, 0x0BA0}, {0x2206, 0x0C05}, {0x2206, 0xE38A}, {0x2206, 0xD6AE},
{0x2206, 0x03E3}, {0x2206, 0x8AD7}, {0x2206, 0xEF13}, {0x2206, 0xBF34},
{0x2206, 0xCB02}, {0x2206, 0x2CA2}, {0x2206, 0xEF13}, {0x2206, 0x0D11},
{0x2206, 0xBF85}, {0x2206, 0x6702}, {0x2206, 0x2CA2}, {0x2206, 0xEF13},
{0x2206, 0x0D14}, {0x2206, 0xBF85}, {0x2206, 0x6402}, {0x2206, 0x2CA2},
{0x2206, 0xEF13}, {0x2206, 0x0D17}, {0x2206, 0xBF85}, {0x2206, 0x6A02},
{0x2206, 0x2CA2}, {0x2206, 0xFD04}, {0x2206, 0xF8E0}, {0x2206, 0x8B85},
{0x2206, 0xAD27}, {0x2206, 0x2DE0}, {0x2206, 0xE036}, {0x2206, 0xE1E0},
{0x2206, 0x37E1}, {0x2206, 0x8B73}, {0x2206, 0x1F10}, {0x2206, 0x9E20},
{0x2206, 0xE48B}, {0x2206, 0x73AC}, {0x2206, 0x200B}, {0x2206, 0xAC21},
{0x2206, 0x0DAC}, {0x2206, 0x250F}, {0x2206, 0xAC27}, {0x2206, 0x0EAE},
{0x2206, 0x0F02}, {0x2206, 0x84CC}, {0x2206, 0xAE0A}, {0x2206, 0x0284},
{0x2206, 0xD1AE}, {0x2206, 0x05AE}, {0x2206, 0x0302}, {0x2206, 0x84D8},
{0x2206, 0xFC04}, {0x2206, 0xEE8B}, {0x2206, 0x6800}, {0x2206, 0x0402},
{0x2206, 0x84E5}, {0x2206, 0x0285}, {0x2206, 0x2804}, {0x2206, 0x0285},
{0x2206, 0x4904}, {0x2206, 0xEE8B}, {0x2206, 0x6800}, {0x2206, 0xEE8B},
{0x2206, 0x6902}, {0x2206, 0x04F8}, {0x2206, 0xF9E0}, {0x2206, 0x8B85},
{0x2206, 0xAD26}, {0x2206, 0x38D0}, {0x2206, 0x0B02}, {0x2206, 0x2B4D},
{0x2206, 0x5882}, {0x2206, 0x7882}, {0x2206, 0x9F2D}, {0x2206, 0xE08B},
{0x2206, 0x68E1}, {0x2206, 0x8B69}, {0x2206, 0x1F10}, {0x2206, 0x9EC8},
{0x2206, 0x10E4}, {0x2206, 0x8B68}, {0x2206, 0xE0E0}, {0x2206, 0x00E1},
{0x2206, 0xE001}, {0x2206, 0xF727}, {0x2206, 0xE4E0}, {0x2206, 0x00E5},
{0x2206, 0xE001}, {0x2206, 0xE2E0}, {0x2206, 0x20E3}, {0x2206, 0xE021},
{0x2206, 0xAD30}, {0x2206, 0xF7F6}, {0x2206, 0x27E4}, {0x2206, 0xE000},
{0x2206, 0xE5E0}, {0x2206, 0x01FD}, {0x2206, 0xFC04}, {0x2206, 0xF8FA},
{0x2206, 0xEF69}, {0x2206, 0xE08B}, {0x2206, 0x86AD}, {0x2206, 0x2212},
{0x2206, 0xE0E0}, {0x2206, 0x14E1}, {0x2206, 0xE015}, {0x2206, 0xAD26},
{0x2206, 0x9CE1}, {0x2206, 0x85E0}, {0x2206, 0xBF85}, {0x2206, 0x6D02},
{0x2206, 0x2CA2}, {0x2206, 0xEF96}, {0x2206, 0xFEFC}, {0x2206, 0x04F8},
{0x2206, 0xFAEF}, {0x2206, 0x69E0}, {0x2206, 0x8B86}, {0x2206, 0xAD22},
{0x2206, 0x09E1}, {0x2206, 0x85E1}, {0x2206, 0xBF85}, {0x2206, 0x6D02},
{0x2206, 0x2CA2}, {0x2206, 0xEF96}, {0x2206, 0xFEFC}, {0x2206, 0x0464},
{0x2206, 0xE48C}, {0x2206, 0xFDE4}, {0x2206, 0x80CA}, {0x2206, 0xE480},
{0x2206, 0x66E0}, {0x2206, 0x8E70}, {0x2206, 0xE076}, {0x2205, 0xE142},
{0x2206, 0x0701}, {0x2205, 0xE140}, {0x2206, 0x0405}, {0x220F, 0x0000},
{0x221F, 0x0000}, {0x2200, 0x1340}, {0x133E, 0x000E}, {0x133F, 0x0010},
{0x13EB, 0x11BB}, {0x13E0, 0x0010}
};
/*End of ChipData30[][2]*/

rtk_uint16 ChipData31[][2]= {
/*Code of Func*/
{0x1B03, 0x0876}, {0x1200, 0x7FC4}, {0x1305, 0xC000}, {0x121E, 0x03CA},
{0x1233, 0x0352}, {0x1234, 0x0064}, {0x1237, 0x0096}, {0x1238, 0x0078},
{0x1239, 0x0084}, {0x123A, 0x0030}, {0x205F, 0x0002}, {0x2059, 0x1A00},
{0x205F, 0x0000}, {0x207F, 0x0002}, {0x2077, 0x0000}, {0x2078, 0x0000},
{0x2079, 0x0000}, {0x207A, 0x0000}, {0x207B, 0x0000}, {0x207F, 0x0000},
{0x205F, 0x0002}, {0x2053, 0x0000}, {0x2054, 0x0000}, {0x2055, 0x0000},
{0x2056, 0x0000}, {0x2057, 0x0000}, {0x205F, 0x0000}, {0x133F, 0x0030},
{0x133E, 0x000E}, {0x221F, 0x0005}, {0x2205, 0x8B86}, {0x2206, 0x800E},
{0x221F, 0x0000}, {0x133F, 0x0010}, {0x12A3, 0x2200}, {0x6107, 0xE58B},
{0x6103, 0xA970}, {0x0018, 0x0F00}, {0x0038, 0x0F00}, {0x0058, 0x0F00},
{0x0078, 0x0F00}, {0x0098, 0x0F00}, {0x133F, 0x0030}, {0x133E, 0x000E},
{0x221F, 0x0005}, {0x2205, 0x8B6E}, {0x2206, 0x0000}, {0x220F, 0x0100},
{0x2205, 0xFFF6}, {0x2206, 0x0080}, {0x2205, 0x8000}, {0x2206, 0x0280},
{0x2206, 0x2BF7}, {0x2206, 0x00E0}, {0x2206, 0xFFF7}, {0x2206, 0xA080},
{0x2206, 0x02AE}, {0x2206, 0xF602}, {0x2206, 0x0153}, {0x2206, 0x0201},
{0x2206, 0x6602}, {0x2206, 0x8044}, {0x2206, 0x0201}, {0x2206, 0x7CE0},
{0x2206, 0x8B8C}, {0x2206, 0xE18B}, {0x2206, 0x8D1E}, {0x2206, 0x01E1},
{0x2206, 0x8B8E}, {0x2206, 0x1E01}, {0x2206, 0xA000}, {0x2206, 0xE4AE},
{0x2206, 0xD8EE}, {0x2206, 0x85C0}, {0x2206, 0x00EE}, {0x2206, 0x85C1},
{0x2206, 0x00EE}, {0x2206, 0x8AFC}, {0x2206, 0x07EE}, {0x2206, 0x8AFD},
{0x2206, 0x73EE}, {0x2206, 0xFFF6}, {0x2206, 0x00EE}, {0x2206, 0xFFF7},
{0x2206, 0xFC04}, {0x2206, 0xF8E0}, {0x2206, 0x8B8E}, {0x2206, 0xAD20},
{0x2206, 0x0302}, {0x2206, 0x8050}, {0x2206, 0xFC04}, {0x2206, 0xF8F9},
{0x2206, 0xE08B}, {0x2206, 0x85AD}, {0x2206, 0x2548}, {0x2206, 0xE08A},
{0x2206, 0xE4E1}, {0x2206, 0x8AE5}, {0x2206, 0x7C00}, {0x2206, 0x009E},
{0x2206, 0x35EE}, {0x2206, 0x8AE4}, {0x2206, 0x00EE}, {0x2206, 0x8AE5},
{0x2206, 0x00E0}, {0x2206, 0x8AFC}, {0x2206, 0xE18A}, {0x2206, 0xFDE2},
{0x2206, 0x85C0}, {0x2206, 0xE385}, {0x2206, 0xC102}, {0x2206, 0x2DAC},
{0x2206, 0xAD20}, {0x2206, 0x12EE}, {0x2206, 0x8AE4}, {0x2206, 0x03EE},
{0x2206, 0x8AE5}, {0x2206, 0xB7EE}, {0x2206, 0x85C0}, {0x2206, 0x00EE},
{0x2206, 0x85C1}, {0x2206, 0x00AE}, {0x2206, 0x1115}, {0x2206, 0xE685},
{0x2206, 0xC0E7}, {0x2206, 0x85C1}, {0x2206, 0xAE08}, {0x2206, 0xEE85},
{0x2206, 0xC000}, {0x2206, 0xEE85}, {0x2206, 0xC100}, {0x2206, 0xFDFC},
{0x2206, 0x0400}, {0x2205, 0xE142}, {0x2206, 0x0701}, {0x2205, 0xE140},
{0x2206, 0x0405}, {0x220F, 0x0000}, {0x221F, 0x0000}, {0x133E, 0x000E},
{0x133F, 0x0010}, {0x13E0, 0x0010}, {0x207F, 0x0002}, {0x2073, 0x1D22},
{0x207F, 0x0000}, {0x133F, 0x0030}, {0x133E, 0x000E}, {0x2200, 0x1340},
{0x133E, 0x000E}, {0x133F, 0x0010}, };
/*End of ChipData31[][2]*/

#if defined(CONFIG_RTL8367B_ASICDRV_TEST)
rtl8367b_vlan4kentrysmi Rtl8370sVirtualVlanTable[RTL8367B_VIDMAX + 1];
#endif

#if !defined(DISABLE_VLAN_SHADOW)
rtl8367b_user_vlan4kentry   user_4kvlan[RTL8367B_VIDMAX + 1];
#endif

/**************************************************************************************************/
/*                                           LOCAL_FUNCTIONS                                      */
/**************************************************************************************************/
u32 rtl8367b_setAsicRegBit(u32 reg, u32 bit, u32 value)
{
	u32 regData = 0;
	u32 retVal;
	retVal = rtl_smi_read(reg, &regData);
	if (0 != retVal)
	{
		RTL8367_DEBUG("Read fail\n");
		return 1;
	}
	
	if(value)
		regData = regData | (1 << bit);
	else
		regData = regData & (~(1 << bit));

	retVal = rtl_smi_write(reg, regData);
	if (0 != retVal)
	{
		RTL8367_DEBUG("Write fail\n");
		return 1;
	}

	return 0;
}

u32 rtl8367b_setAsicRegBits(u32 reg, u32 bits, u32 value)
{
	u32 regData = 0;
	u32 retVal;
	u32 bitsShift;
	u32 valueShifted;

	bitsShift = 0;
	while(!(bits & (1 << bitsShift)))
	{
		bitsShift++;
	}
	valueShifted = value << bitsShift;


	retVal = rtl_smi_read(reg, &regData);
	if (0 != retVal)
	{
		RTL8367_DEBUG("Read fail\n");
		return 1;
	}

	regData = regData & (~bits);
	regData = regData | (valueShifted & bits);

	retVal = rtl_smi_write(reg, regData);
	if (0 != retVal)
	{
		RTL8367_DEBUG("Read fail\n");
		return 1;
	}

	return 0;
}

/* Function Name:
 *      rtl8367b_setAsicReg
 * Description:
 *      Set content of asic register
 * Input:
 *      reg 	- register's address
 *      value 	- Value setting to register
 * Output:
 *      None
 * Return:
 *      RT_ERR_OK 		- Success
 *      RT_ERR_SMI  	- SMI access error
 * Note:
 *      The value will be set to ASIC mapping address only and it is always return RT_ERR_OK while setting un-mapping address registers
 */
ret_t rtl8367b_setAsicReg(rtk_uint32 reg, rtk_uint32 value)
{
	ret_t retVal;

	retVal = rtl_smi_write(reg, value);
	if(retVal != RT_ERR_OK)
		return RT_ERR_SMI;
	
	return RT_ERR_OK;
}

/* Function Name:
 *      rtl8367b_getAsicReg
 * Description:
 *      Get content of asic register
 * Input:
 *      reg 	- register's address
 *      value 	- Value setting to register
 * Output:
 *      None
 * Return:
 *      RT_ERR_OK 		- Success
 *      RT_ERR_SMI  	- SMI access error
 * Note:
 *      Value 0x0000 will be returned for ASIC un-mapping address
 */
ret_t rtl8367b_getAsicReg(rtk_uint32 reg, rtk_uint32 *pValue)
{
	rtk_uint32 regData;
	ret_t retVal;

	retVal = rtl_smi_read(reg, &regData);
	if(retVal != RT_ERR_OK)
		return RT_ERR_SMI;
	
	*pValue = regData;
	return RT_ERR_OK;
}

/* Function Name:
 *      rtl8367b_setAsicPHYReg
 * Description:
 *      Set PHY registers
 * Input:
 *      phyNo 	- Physical port number (0~4)
 *      phyAddr - PHY address (0~31)
 *      phyData - Writing data
 * Output:
 *      None
 * Return:
 *      RT_ERR_OK 				- Success
 *      RT_ERR_SMI  			- SMI access error
 *      RT_ERR_PHY_REG_ID  		- invalid PHY address
 *      RT_ERR_PHY_ID  			- invalid PHY no
 *      RT_ERR_BUSYWAIT_TIMEOUT - PHY access busy
 * Note:
 *      None
 */
ret_t rtl8367b_setAsicPHYReg( rtk_uint32 phyNo, rtk_uint32 phyAddr, rtk_uint32 value)
{
	rtk_uint32 regAddr;

    if(phyNo > RTL8367B_PHY_INTERNALNOMAX)
        return RT_ERR_PORT_ID;

    if(phyAddr > RTL8367B_PHY_REGNOMAX)
        return RT_ERR_PHY_REG_ID;

    regAddr = 0x2000 + (phyNo << 5) + phyAddr;

    return rtl8367b_setAsicReg(regAddr, value);
}

/* Function Name:
 *      rtl8367b_getAsicPHYReg
 * Description:
 *      Get PHY registers
 * Input:
 *      phyNo 	- Physical port number (0~4)
 *      phyAddr - PHY address (0~31)
 *      pRegData - Writing data
 * Output:
 *      None
 * Return:
 *      RT_ERR_OK 				- Success
 *      RT_ERR_SMI  			- SMI access error
 *      RT_ERR_PHY_REG_ID  		- invalid PHY address
 *      RT_ERR_PHY_ID  			- invalid PHY no
 *      RT_ERR_BUSYWAIT_TIMEOUT - PHY access busy
 * Note:
 *      None
 */
ret_t rtl8367b_getAsicPHYReg( rtk_uint32 phyNo, rtk_uint32 phyAddr, rtk_uint32 *value)
{
	rtk_uint32 regAddr;

    if(phyNo > RTL8367B_PHY_INTERNALNOMAX)
        return RT_ERR_PORT_ID;

    if(phyAddr > RTL8367B_PHY_REGNOMAX)
        return RT_ERR_PHY_REG_ID;

    regAddr = 0x2000 + (phyNo << 5) + phyAddr;

    return rtl8367b_getAsicReg(regAddr, value);
}

/* Function Name:
 *      rtk_port_phyTestModeAll_set
 * Description:
 *      Set PHY in test mode.
 * Input:
 *      port - port id.
 *      mode - PHY test mode 0:normal 1:test mode 1 2:test mode 2 3: test mode 3 4:test mode 4 5~7:reserved
 * Output:
 *      None
 * Return:
 *      RT_ERR_OK              	- OK
 *      RT_ERR_FAILED          	- Failed
 *      RT_ERR_SMI             	- SMI access error
 *      RT_ERR_PORT_ID 			- Invalid port number.
 *      RT_ERR_BUSYWAIT_TIMEOUT - PHY access busy
 *      RT_ERR_NOT_ALLOWED      - The Setting is not allowed, caused by set more than 1 port in Test mode.
 * Note:
 *      Set PHY in test mode and only one PHY can be in test mode at the same time.
 *      It means API will return FAILED if other PHY is in test mode.
 *      This API only provide test mode 1 & 4 setup, and if users want other test modes,
 *      please contact realtek FAE.
 */
rtk_api_ret_t rtk_port_phyTestModeAll_set(rtk_port_t port, rtk_port_phy_test_mode_t mode)
{
    rtk_uint32          data, i, index, phy, reg;
    rtk_api_ret_t       retVal;
    CONST_T rtk_uint16 ParaTM_1[][2] = { {0x205F,0x0002}, {0x2053,0xAA00}, {0x2054,0xAA00}, {0x2055,0xAA00},
                                         {0x2056,0xAA00}, {0x2057,0xAA00}, {0x205F,0x0002} };

    if (port > RTK_PHY_ID_MAX)
        return RT_ERR_PORT_ID;

    if(mode >= PHY_TEST_MODE_END)
        return RT_ERR_INPUT;

    if (PHY_TEST_MODE_NORMAL != mode)
    {
        /* Other port should be Normal mode */
        for(i = 0; i <= RTK_PHY_ID_MAX; i++)
        {
            if(i != port)
            {
                if ((retVal = rtl8367b_setAsicPHYReg(i, 31, 0)) != RT_ERR_OK)
                    return retVal;

                if ((retVal = rtl8367b_getAsicPHYReg(i, 9, &data)) != RT_ERR_OK)
                    return retVal;

                if((data & 0xE000) != 0)
                    return RT_ERR_NOT_ALLOWED;
            }
        }
    }

    if (PHY_TEST_MODE_1 == mode)
    {
        for (index = 0; index < (sizeof(ParaTM_1) / ((sizeof(rtk_uint16))*2)); index++)
        {
            phy = (ParaTM_1[index][0] - 0x2000) / 0x0020;
            reg = (ParaTM_1[index][0] - 0x2000) % 0x0020;
            if ((retVal = rtl8367b_setAsicPHYReg(phy, reg, ParaTM_1[index][1])) != RT_ERR_OK)
                return retVal;
        }
    }

    if ((retVal = rtl8367b_setAsicPHYReg(port, 31, 0)) != RT_ERR_OK)
        return retVal;

    if ((retVal = rtl8367b_getAsicPHYReg(port, 9, &data)) != RT_ERR_OK)
        return retVal;

    data &= ~0xE000;
    data |= (mode << 13);
    if ((retVal = rtl8367b_setAsicPHYReg(port, 9, data)) != RT_ERR_OK)
        return retVal;

    if (PHY_TEST_MODE_3 == mode)
    {
        if ((retVal = rtl8367b_setAsicPHYReg(port, 31, 2)) != RT_ERR_OK)
            return retVal;

        if ((retVal = rtl8367b_setAsicPHYReg(port, 1, 0x065A)) != RT_ERR_OK)
            return retVal;
    }

    return RT_ERR_OK;
}

/* Function Name:
 *      rtk_port_phyTestModeAll_get
 * Description:
 *      Get PHY in which test mode.
 * Input:
 *      port - Port id.
 * Output:
 *      mode - PHY test mode 0:normal 1:test mode 1 2:test mode 2 3: test mode 3 4:test mode 4 5~7:reserved
 * Return:
 *      RT_ERR_OK              	- OK
 *      RT_ERR_FAILED          	- Failed
 *      RT_ERR_SMI             	- SMI access error
 *      RT_ERR_PORT_ID 			- Invalid port number.
 *      RT_ERR_INPUT 			- Invalid input parameters.
 *      RT_ERR_BUSYWAIT_TIMEOUT - PHY access busy
 * Note:
 *      Get test mode of PHY from register setting 9.15 to 9.13.
 */
rtk_api_ret_t rtk_port_phyTestModeAll_get(rtk_port_t port, rtk_port_phy_test_mode_t *pMode)
{
    rtk_uint32      data;
    rtk_api_ret_t   retVal;

    if (port > RTK_PHY_ID_MAX)
        return RT_ERR_PORT_ID;

    if ((retVal = rtl8367b_setAsicPHYReg(port, 31, 0)) != RT_ERR_OK)
        return retVal;

    if ((retVal = rtl8367b_getAsicPHYReg(port, 9, &data)) != RT_ERR_OK)
        return retVal;

    *pMode = (data & 0xE000) >> 13;

    return RT_ERR_OK;
}

static rtk_api_ret_t _rtk_switch_init_setreg(rtk_uint32 reg, rtk_uint32 data)
{
    rtk_api_ret_t   retVal;

    if((retVal = rtl8367b_setAsicReg(reg, data) != RT_ERR_OK))
            return retVal;

    return RT_ERR_OK;
}

void regDebug(int reg)
{
#if 0
	int data;
	rw_rf_reg(0, reg, &data);
	printf("rf reg <%d> = 0x%x\n", reg, data);
#endif
}

void _rtl8367b_Vlan4kStUser2Smi(rtl8367b_user_vlan4kentry *pUserVlan4kEntry, rtl8367b_vlan4kentrysmi *pSmiVlan4kEntry)
{
    pSmiVlan4kEntry->mbr        = pUserVlan4kEntry->mbr;
    pSmiVlan4kEntry->untag      = pUserVlan4kEntry->untag;
 	pSmiVlan4kEntry->fid_msti   = pUserVlan4kEntry->fid_msti;
 	pSmiVlan4kEntry->vbpen      = pUserVlan4kEntry->vbpen;
	pSmiVlan4kEntry->vbpri      = pUserVlan4kEntry->vbpri;
	pSmiVlan4kEntry->envlanpol  = pUserVlan4kEntry->envlanpol;
	pSmiVlan4kEntry->meteridx   = pUserVlan4kEntry->meteridx;
	pSmiVlan4kEntry->ivl_svl	= pUserVlan4kEntry->ivl_svl;

}

void _rtl8367b_Vlan4kStSmi2User(rtl8367b_vlan4kentrysmi *pSmiVlan4kEntry, rtl8367b_user_vlan4kentry *pUserVlan4kEntry)
{
    pUserVlan4kEntry->mbr    	= pSmiVlan4kEntry->mbr;
    pUserVlan4kEntry->untag    	= pSmiVlan4kEntry->untag;
 	pUserVlan4kEntry->fid_msti  = pSmiVlan4kEntry->fid_msti;
 	pUserVlan4kEntry->vbpen     = pSmiVlan4kEntry->vbpen;
	pUserVlan4kEntry->vbpri     = pSmiVlan4kEntry->vbpri;
	pUserVlan4kEntry->envlanpol = pSmiVlan4kEntry->envlanpol;
	pUserVlan4kEntry->meteridx  = pSmiVlan4kEntry->meteridx;
	pUserVlan4kEntry->ivl_svl  	= pSmiVlan4kEntry->ivl_svl;
}

void _rtl8367b_VlanMCStSmi2User(rtl8367b_vlanconfigsmi *pSmiVlanCfg, rtl8367b_vlanconfiguser *pVlanCg)
{
	pVlanCg->mbr			= pSmiVlanCfg->mbr;
	pVlanCg->fid_msti		= pSmiVlanCfg->fid_msti;
	pVlanCg->evid			= pSmiVlanCfg->evid;
    pVlanCg->meteridx		= pSmiVlanCfg->meteridx;
	pVlanCg->envlanpol		= pSmiVlanCfg->envlanpol;
	pVlanCg->vbpri			= pSmiVlanCfg->vbpri;
	pVlanCg->vbpen			= pSmiVlanCfg->vbpen;
}

void _rtl8367b_VlanMCStUser2Smi(rtl8367b_vlanconfiguser *pVlanCg, rtl8367b_vlanconfigsmi *pSmiVlanCfg)
{
	pSmiVlanCfg->mbr 		= pVlanCg->mbr;
	pSmiVlanCfg->fid_msti 	= pVlanCg->fid_msti;
	pSmiVlanCfg->evid 		= pVlanCg->evid;
	pSmiVlanCfg->meteridx 	= pVlanCg->meteridx;
	pSmiVlanCfg->envlanpol 	= pVlanCg->envlanpol;
	pSmiVlanCfg->vbpri 		= pVlanCg->vbpri;
	pSmiVlanCfg->vbpen 		= pVlanCg->vbpen;
}

ret_t rtl8367b_setAsicVlan4kEntry(rtl8367b_user_vlan4kentry *pVlan4kEntry )
{
    rtl8367b_vlan4kentrysmi vlan_4k_entry;
	rtk_uint32					page_idx;
	rtk_uint16					*tableAddr;
	ret_t 					retVal;
	rtk_uint32 					regData;

    if(pVlan4kEntry->vid > RTL8367B_VIDMAX)
        return RT_ERR_VLAN_VID;

    if(pVlan4kEntry->mbr > RTL8367B_PORTMASK)
        return RT_ERR_PORT_MASK;

    if(pVlan4kEntry->untag > RTL8367B_PORTMASK)
        return RT_ERR_PORT_MASK;

    if(pVlan4kEntry->fid_msti > RTL8367B_FIDMAX)
        return RT_ERR_L2_FID;

    if(pVlan4kEntry->meteridx > RTL8367B_METERMAX)
        return RT_ERR_FILTER_METER_ID;

    if(pVlan4kEntry->vbpri > RTL8367B_PRIMAX)
        return RT_ERR_QOS_INT_PRIORITY;

    memset(&vlan_4k_entry, 0x00, sizeof(rtl8367b_vlan4kentrysmi));
    _rtl8367b_Vlan4kStUser2Smi(pVlan4kEntry, &vlan_4k_entry);

	/* Prepare Data */
	tableAddr = (rtk_uint16 *)&vlan_4k_entry;
	for(page_idx = 0; page_idx < (sizeof(rtl8367b_vlan4kentrysmi) / 2); page_idx++)
	{
		regData = *tableAddr;
		retVal = rtl8367b_setAsicReg(RTL8367B_TABLE_ACCESS_WRDATA_BASE + page_idx, regData);
		if(retVal != RT_ERR_OK)
			return retVal;

		tableAddr++;
	}

	/* Write Address (VLAN_ID) */
	regData = pVlan4kEntry->vid;
	retVal = rtl8367b_setAsicReg(RTL8367B_TABLE_ACCESS_ADDR_REG, regData);
	if(retVal != RT_ERR_OK)
		return retVal;

	/* Write Command */
	retVal = rtl8367b_setAsicRegBits(RTL8367B_TABLE_ACCESS_CTRL_REG, RTL8367B_TABLE_TYPE_MASK | RTL8367B_COMMAND_TYPE_MASK,RTL8367B_TABLE_ACCESS_REG_DATA(TB_OP_WRITE,TB_TARGET_CVLAN));
	if(retVal != RT_ERR_OK)
		return retVal;

#if defined(CONFIG_RTL8367B_ASICDRV_TEST)
    memcpy(&Rtl8370sVirtualVlanTable[pVlan4kEntry->vid], &vlan_4k_entry, sizeof(rtl8367b_vlan4kentrysmi));
#endif

#if !defined(DISABLE_VLAN_SHADOW)
    memcpy(&user_4kvlan[pVlan4kEntry->vid], pVlan4kEntry, sizeof(rtl8367b_user_vlan4kentry));
#endif

    return RT_ERR_OK;
}

ret_t rtl8367b_getAsicVlan4kEntry(rtl8367b_user_vlan4kentry *pVlan4kEntry )
{
#if defined(DISABLE_VLAN_SHADOW)
	rtl8367b_vlan4kentrysmi 	vlan_4k_entry;
	rtk_uint32				page_idx;
	rtk_uint16				*tableAddr;
	ret_t 					retVal;
	rtk_uint32 				regData;

    if(pVlan4kEntry->vid > RTL8367B_VIDMAX)
        return RT_ERR_VLAN_VID;

	/* Write Address (VLAN_ID) */
	regData = pVlan4kEntry->vid;
	retVal = rtl8367b_setAsicReg(RTL8367B_TABLE_ACCESS_ADDR_REG, regData);
	if(retVal != RT_ERR_OK)
		return retVal;

	/* Read Command */
	retVal = rtl8367b_setAsicRegBits(RTL8367B_TABLE_ACCESS_CTRL_REG, RTL8367B_TABLE_TYPE_MASK | RTL8367B_COMMAND_TYPE_MASK, RTL8367B_TABLE_ACCESS_REG_DATA(TB_OP_READ,TB_TARGET_CVLAN));
	if(retVal != RT_ERR_OK)
		return retVal;

	/* Check ASIC Command */
	retVal = rtl8367b_getAsicRegBit(RTL8367B_TABLE_ACCESS_STATUS_REG, RTL8367B_TABLE_LUT_ADDR_BUSY_FLAG_OFFSET,&regData);
	if(retVal != RT_ERR_OK)
        return RT_ERR_BUSYWAIT_TIMEOUT;

	/* Read VLAN data from register */
	tableAddr = (rtk_uint16 *)&vlan_4k_entry;
	for(page_idx = 0; page_idx < (sizeof(rtl8367b_vlan4kentrysmi) / 2); page_idx++)
	{
		retVal = rtl8367b_getAsicReg(RTL8367B_TABLE_ACCESS_RDDATA_BASE + page_idx, &regData);
		if(retVal != RT_ERR_OK)
			return retVal;

		*tableAddr = regData;
		tableAddr++;
	}

	_rtl8367b_Vlan4kStSmi2User(&vlan_4k_entry, pVlan4kEntry);

#else

    rtk_uint16  vid;

    vid = pVlan4kEntry->vid;
    memcpy(pVlan4kEntry, &user_4kvlan[pVlan4kEntry->vid], sizeof(rtl8367b_user_vlan4kentry));
    pVlan4kEntry->vid = vid;

#endif

#if defined(CONFIG_RTL8367B_ASICDRV_TEST)
    _rtl8367b_Vlan4kStSmi2User(&Rtl8370sVirtualVlanTable[pVlan4kEntry->vid], pVlan4kEntry);
#endif

    return RT_ERR_OK;
}

ret_t rtl8367b_getAsicVlanMemberConfig(rtk_uint32 index, rtl8367b_vlanconfiguser *pVlanCg)
{
    ret_t  retVal;
    rtk_uint32 page_idx;
    rtk_uint32 regAddr;
    rtk_uint32 regData;
    rtk_uint16 *tableAddr;
    rtl8367b_vlanconfigsmi  smi_vlancfg;

    if(index > RTL8367B_CVIDXMAX)
		return RT_ERR_VLAN_ENTRY_NOT_FOUND;

    memset(&smi_vlancfg, 0x00, sizeof(rtl8367b_vlanconfigsmi));
    tableAddr  = (rtk_uint16*)&smi_vlancfg;

    for(page_idx = 0; page_idx < 4; page_idx++)  /* 4 pages per VLAN Member Config */
    {
        regAddr = RTL8367B_VLAN_MEMBER_CONFIGURATION_BASE + (index * 4) + page_idx;

        retVal = rtl8367b_getAsicReg(regAddr, &regData);
        if(retVal != RT_ERR_OK)
            return retVal;

        *tableAddr = (rtk_uint16)regData;
        tableAddr++;
    }

    _rtl8367b_VlanMCStSmi2User(&smi_vlancfg, pVlanCg);
    return RT_ERR_OK;
}

ret_t rtl8367b_setAsicVlanMemberConfig(rtk_uint32 index, rtl8367b_vlanconfiguser *pVlanCg)
{
	ret_t  retVal;
	rtk_uint32 regAddr;
	rtk_uint32 regData;
	rtk_uint16 *tableAddr;
    rtk_uint32 page_idx;
    rtl8367b_vlanconfigsmi  smi_vlancfg;

    /* Error Checking  */
	if(index > RTL8367B_CVIDXMAX)
        return RT_ERR_VLAN_ENTRY_NOT_FOUND;

    if(pVlanCg->evid > RTL8367B_EVIDMAX)
        return RT_ERR_INPUT;


    if(pVlanCg->mbr > RTL8367B_PORTMASK)
        return RT_ERR_PORT_MASK;

    if(pVlanCg->fid_msti > RTL8367B_FIDMAX)
        return RT_ERR_L2_FID;

    if(pVlanCg->meteridx > RTL8367B_METERMAX)
        return RT_ERR_FILTER_METER_ID;

    if(pVlanCg->vbpri > RTL8367B_PRIMAX)
        return RT_ERR_QOS_INT_PRIORITY;

    memset(&smi_vlancfg, 0x00, sizeof(rtl8367b_vlanconfigsmi));
    _rtl8367b_VlanMCStUser2Smi(pVlanCg, &smi_vlancfg);
    tableAddr = (rtk_uint16*)&smi_vlancfg;

    for(page_idx = 0; page_idx < 4; page_idx++)  /* 4 pages per VLAN Member Config */
    {
        regAddr = RTL8367B_VLAN_MEMBER_CONFIGURATION_BASE + (index * 4) + page_idx;
    	regData = *tableAddr;

    	retVal = rtl8367b_setAsicReg(regAddr, regData);
    	if(retVal != RT_ERR_OK)
            return retVal;

        tableAddr++;
    }

	return RT_ERR_OK;
}

ret_t rtl8367b_setAsicVlanPortBasedVID(rtk_uint32 port, rtk_uint32 index, rtk_uint32 pri)
{
    rtk_uint32 regAddr, bit_mask;
    ret_t  retVal;

    if(port > RTL8367B_PORTIDMAX)
        return RT_ERR_PORT_ID;

    if(index > RTL8367B_CVIDXMAX)
        return RT_ERR_VLAN_ENTRY_NOT_FOUND;

    if(pri > RTL8367B_PRIMAX)
        return RT_ERR_QOS_INT_PRIORITY;

    regAddr = RTL8367B_VLAN_PVID_CTRL_REG(port);
    bit_mask = RTL8367B_PORT_VIDX_MASK(port);
    retVal = rtl8367b_setAsicRegBits(regAddr, bit_mask, index);
    if(retVal != RT_ERR_OK)
        return retVal;

    regAddr = RTL8367B_VLAN_PORTBASED_PRIORITY_REG(port);
    bit_mask = RTL8367B_VLAN_PORTBASED_PRIORITY_MASK(port);
    retVal = rtl8367b_setAsicRegBits(regAddr, bit_mask, pri);
    if(retVal != RT_ERR_OK)
        return retVal;

    return RT_ERR_OK;
}

ret_t rtl8367b_getAsicVlanPortBasedVID(rtk_uint32 port, rtk_uint32 *pIndex, rtk_uint32 *pPri)
{
    rtk_uint32 regAddr,bit_mask;
    ret_t  retVal;

    if(port > RTL8367B_PORTIDMAX)
        return RT_ERR_PORT_ID;

    regAddr = RTL8367B_VLAN_PVID_CTRL_REG(port);
    bit_mask = RTL8367B_PORT_VIDX_MASK(port);
    retVal = rtl8367b_getAsicRegBits(regAddr, bit_mask, pIndex);
    if(retVal != RT_ERR_OK)
        return retVal;

    regAddr = RTL8367B_VLAN_PORTBASED_PRIORITY_REG(port);
    bit_mask = RTL8367B_VLAN_PORTBASED_PRIORITY_MASK(port);
    retVal = rtl8367b_getAsicRegBits(regAddr, bit_mask, pPri);
    if(retVal != RT_ERR_OK)
        return retVal;

    return RT_ERR_OK;
}

ret_t rtl8367b_getAsicRegBit(rtk_uint32 reg, rtk_uint32 bit, rtk_uint32 *pValue)
{

#if 0//defined(RTK_X86_ASICDRV)

	rtk_uint32 regData;
	ret_t retVal;

	if(bit >= RTL8367B_REGBITLENGTH)
		return RT_ERR_INPUT;

	retVal = Access_Read(reg, 2, &regData);
	if(TRUE != retVal)
		return RT_ERR_SMI;

	*pValue = (regData & (0x1 << bit)) >> bit;

	if(0x8367B == cleDebuggingDisplay)
		PRINT("R[0x%4.4x]=0x%4.4x\n", reg, regData);

#elif 0//defined(CONFIG_RTL8367B_ASICDRV_TEST)

	if(bit >= RTL8367B_REGBITLENGTH)
		return RT_ERR_INPUT;

	if(reg >= CLE_VIRTUAL_REG_SIZE)
		return RT_ERR_OUT_OF_RANGE;

	*pValue = (CleVirtualReg[reg] & (0x1 << bit)) >> bit;

	if(0x8367B == cleDebuggingDisplay)
		PRINT("R[0x%4.4x]=0x%4.4x\n", reg, CleVirtualReg[reg]);

#elif 0//defined(EMBEDDED_SUPPORT)
    rtk_uint16 tmp;

    if(reg > RTL8367B_REGDATAMAX )
	    return RT_ERR_INPUT;

	tmp = getReg(reg);
	tmp = tmp >> bitIdx;
	tmp &= 1;
	*value = tmp;
#else
	rtk_uint32 regData;
	ret_t retVal;

	retVal = rtl_smi_read(reg, &regData);
	if(retVal != RT_ERR_OK)
		return RT_ERR_SMI;

  #if 0 //def CONFIG_RTL865X_CLE
	if(0x8367B == cleDebuggingDisplay)
		PRINT("R[0x%4.4x]=0x%4.4x\n", reg, regData);
  #endif

	*pValue = (regData & (0x1 << bit)) >> bit;

#endif
	return RT_ERR_OK;
}

ret_t rtl8367b_getAsicRegBits(rtk_uint32 reg, rtk_uint32 bits, rtk_uint32 *pValue)
{

#if 0//defined(RTK_X86_ASICDRV)

	rtk_uint32 regData;
	ret_t retVal;
	rtk_uint32 bitsShift;

	if(bits >= (1 << RTL8367B_REGBITLENGTH) )
		return RT_ERR_INPUT;

	bitsShift = 0;
	while(!(bits & (1 << bitsShift)))
	{
		bitsShift++;
		if(bitsShift >= RTL8367B_REGBITLENGTH)
			return RT_ERR_INPUT;
	}

	retVal = Access_Read(reg, 2, &regData);
	if(TRUE != retVal)
		return RT_ERR_SMI;

	*pValue = (regData & bits) >> bitsShift;

	if(0x8367B == cleDebuggingDisplay)
		PRINT("R[0x%4.4x]=0x%4.4x\n", reg, regData);

#elif 0//defined(CONFIG_RTL8367B_ASICDRV_TEST)
	rtk_uint32 bitsShift;

	if(bits >= (1 << RTL8367B_REGBITLENGTH) )
		return RT_ERR_INPUT;

	bitsShift = 0;
	while(!(bits & (1 << bitsShift)))
	{
		bitsShift++;
		if(bitsShift >= RTL8367B_REGBITLENGTH)
			return RT_ERR_INPUT;
	}

	if(reg >= CLE_VIRTUAL_REG_SIZE)
		return RT_ERR_OUT_OF_RANGE;

	 *pValue = (CleVirtualReg[reg] & bits) >> bitsShift;

	if(0x8367B == cleDebuggingDisplay)
		PRINT("R[0x%4.4x]=0x%4.4x\n", reg, CleVirtualReg[reg]);

#elif 0//defined(EMBEDDED_SUPPORT)
    rtk_uint32 regData;
    rtk_uint32 bitsShift;

    if(reg > RTL8367B_REGDATAMAX )
	    return RT_ERR_INPUT;

    if(bits >= (1UL << RTL8367B_REGBITLENGTH) )
        return RT_ERR_INPUT;

    bitsShift = 0;
    while(!(bits & (1UL << bitsShift)))
    {
        bitsShift++;
        if(bitsShift >= RTL8367B_REGBITLENGTH)
            return RT_ERR_INPUT;
    }

    regData = getReg(reg);
    *value = (regData & bits) >> bitsShift;

#else
	rtk_uint32 regData;
	ret_t retVal;
	rtk_uint32 bitsShift;

	if(bits>= (1<<RTL8367B_REGBITLENGTH) )
		return RT_ERR_INPUT;

	bitsShift = 0;
	while(!(bits & (1 << bitsShift)))
	{
		bitsShift++;
		if(bitsShift >= RTL8367B_REGBITLENGTH)
			return RT_ERR_INPUT;
	}

	retVal = rtl_smi_read(reg, &regData);
	if(retVal != RT_ERR_OK) return RT_ERR_SMI;

	*pValue = (regData & bits) >> bitsShift;
  #if 0//def CONFIG_RTL865X_CLE
	if(0x8367B == cleDebuggingDisplay)
		PRINT("R[0x%4.4x]=0x%4.4x\n",reg, regData);
  #endif

#endif
	return RT_ERR_OK;
}

ret_t rtl8367b_getAsic1xGuestVidx(rtk_uint32 *pIndex)
{
	return rtl8367b_getAsicRegBits(RTL8367B_DOT1X_CFG_REG, RTL8367B_DOT1X_GVIDX_MASK, pIndex);
}

ret_t rtl8367b_getAsic1xProcConfig(rtk_uint32 port, rtk_uint32* pProc)
{
	if(port >= RTL8367B_PORTNO)
		return RT_ERR_PORT_ID;

	return rtl8367b_getAsicRegBits(RTL8367B_DOT1X_UNAUTH_ACT_BASE, RTL8367B_DOT1X_UNAUTH_ACT_MASK(port),pProc);
}

ret_t rtl8367b_getAsicVlanPortAndProtocolBased(rtk_uint32 port, rtk_uint32 index, rtl8367b_protocolvlancfg *pPpbCfg)
{
	rtk_uint32  reg_addr, bit_mask, bit_value;
	ret_t   retVal;

	/* Error Checking */
	if(port > RTL8367B_PORTIDMAX)
		return RT_ERR_PORT_ID;

	if(index > RTL8367B_PROTOVLAN_GIDX_MAX)
		return RT_ERR_VLAN_PROTO_AND_PORT;

	if(pPpbCfg == NULL)
		return RT_ERR_INPUT;

	/* Valid bit */
	reg_addr  = RTL8367B_VLAN_PPB_VALID_REG(index);
	bit_mask  = 0x0001 << port;
	retVal    = rtl8367b_getAsicRegBits(reg_addr, bit_mask, &bit_value);
	if(retVal != RT_ERR_OK)
		return retVal;

	pPpbCfg->valid = bit_value;

	/* CVLAN index */
	reg_addr = RTL8367B_VLAN_PPB_CTRL_REG(index,port);
	bit_mask = RTL8367B_VLAN_PPB_CTRL_MASK(port);
	retVal = rtl8367b_getAsicRegBits(reg_addr, bit_mask, &bit_value);
	if(retVal != RT_ERR_OK)
		return retVal;

	pPpbCfg->vlan_idx = bit_value;


	/* priority */
	reg_addr = RTL8367B_VLAN_PPB_PRIORITY_ITEM_REG(port,index);
	bit_mask = RTL8367B_VLAN_PPB_PRIORITY_ITEM_MASK(port);
	retVal = rtl8367b_getAsicRegBits(reg_addr, bit_mask, &bit_value);
	if(retVal != RT_ERR_OK)
		return retVal;

	pPpbCfg->priority = bit_value;
    return RT_ERR_OK;
}

ret_t rtl8367b_setAsicVlanEgressTagMode(rtk_uint32 port, rtl8367b_egtagmode tagMode)
{
    if(port > RTL8367B_PORTIDMAX)
        return RT_ERR_PORT_ID;

    if(tagMode >= EG_TAG_MODE_END)
        return RT_ERR_INPUT;

    return rtl8367b_setAsicRegBits(RTL8367B_PORT_MISC_CFG_REG(port), RTL8367B_VLAN_EGRESS_MDOE_MASK, tagMode);
}

ret_t rtl8367b_setAsicVlanFilter(rtk_uint32 enabled)
{
    return rtl8367b_setAsicRegBit(RTL8367B_REG_VLAN_CTRL, RTL8367B_VLAN_CTRL_OFFSET, enabled);
}

void externalInterfaceDelay()
{
	rtl_smi_write(EXT1_RGMXF, RGMXF_CONF);/* 0xc need more consideration  */
	rtl_smi_write(EXT2_RGMXF, RGMXF_CONF);/* 0xc need more consideration  */
}

void IsSwitchVlanTableBusy()
{
	int j = 0;
	unsigned int value = 0;

	for (j = 0; j < 20; j++) {
            value = *(unsigned long *)(RALINK_ETH_SW_BASE+0x90); //VTCR
	    if ((value & 0x80000000) == 0 ){ //table busy
		break;
	    }
	    udelay(1000);
	}
	if (j == 20)
	    RTL8367_DEBUG("set vlan timeout.\n");
}

void vlanDump()
{
	u32 reck[] = {0x2004,0x2104,0x2204,0x2304,0x2404,0x2504,0x2604,0x2704,
				0x2010,0x2110,0x2210,0x2310,0x2410,0x2510,0x2610,0x2710,
				0x2014,0x2114,0x2214,0x2314,0x2414,0x2514,0x2614,0x2714,
				0x94,0x90,0x100};
	u32 swReg;
	u8 index = 0;
	for (index = 0; index < 27; index++)
	{
		swReg = RALINK_ETH_SW_BASE + reck[index];
		RTL8367_DEBUG("switch reg 0x%x : 0x%08x\n", reck[index], *(unsigned long *)(swReg));
	}
}

rtk_api_ret_t setVlanRtl8367()
{
	u8 index = 0;
	rtk_vlan_t portVID = 0;
	rtk_api_ret_t ret;
	rtk_portmask_t LANPort;
	rtk_portmask_t WANPort;
	rtk_portmask_t untagMsk;
	
	/* port map:7~0 -> WLXL,LLLW */
	/* add port 1~4 and 6 to VLAN 50 as LAN. 0101,1110 */
	LANPort.bits[0] = 0x5e;
	untagMsk.bits[0] = 0x1e;
	if ((ret = rtk_vlan_set(LAN_VLAN_ID, LANPort, LANPort, RTK_IVL_MODE_FID)) != RT_ERR_OK)
	{
		RTL8367_ERROR("set LAN VLAN error: 0x%08x...\n", ret);
		return ret;
	}
	/* add port 0 and 7 to VLAN 51 as WAN. 1000,0001 */
	WANPort.bits[0] = 0x81;
	untagMsk.bits[0] = 0x01;
	if ((ret = rtk_vlan_set(WAN_VLAN_ID, WANPort, WANPort, RTK_IVL_MODE_FID)) != RT_ERR_OK)
	{
		RTL8367_ERROR("set WAN VLAN error: 0x%08x...\n", ret);
		return ret;
	}
	/* set port 1~4 and 6 with PVID 50 */
	/* set port 0 and 7 with PVID 51 */
	for (index = 0; index < RTK_MAX_NUM_OF_PORT; index++)
	{
		if (index == 5)
		{
			continue;
		}
		else if (index == 0 || index == 7)
		{
			portVID = WAN_VLAN_PVID;
		}
		else
		{
			portVID = LAN_VLAN_PVID;
		}
		if ((ret = rtk_vlan_portPvid_set(index, portVID, 0)) != RT_ERR_OK)
		{
			RTL8367_ERROR("set port %d PVID error: 0x%08x...\n", index, ret);
			return ret;
		}
	}
}

rtk_api_ret_t setVlanInner()
{
	//LAN/WAN ports as security mode
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x2004) = 0xff0003; //port0
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x2104) = 0xff0003; //port1
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x2204) = 0xff0003; //port2
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x2304) = 0xff0003; //port3
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x2404) = 0xff0003; //port4
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x2504) = 0xff0003; //port5

	//LAN/WAN ports as transparent port
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x2010) = 0x810000c0; //port0
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x2110) = 0x810000c0; //port1
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x2210) = 0x810000c0; //port2
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x2310) = 0x810000c0; //port3
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x2410) = 0x810000c0; //port4
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x2510) = 0x810000c0; //port5
	
	//set CPU/P7 port as user port
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x2610) = 0x81000000; //port6
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x2710) = 0x81000000; //port7
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x2604) = 0x20ff0003; //port6, Egress VLAN Tag Attribution=tagged
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x2704) = 0x20ff0003; //port7, Egress VLAN Tag Attribution=tagged
	
	//set PVID
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x2114) = 0x10003; //port1
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x2214) = 0x10003; //port2
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x2314) = 0x10003; //port3
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x2514) = 0x10003; //port5
#ifdef CONFIG_TP_MODEL_C2V1
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x2014) = 0x10003; //port0
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x2414) = 0x10002; //port4
#elif defined CONFIG_TP_MODEL_C20iV1
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x2014) = 0x10002; //port0
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x2414) = 0x10003; //port4
#endif

	//VLAN member
	//*(unsigned long *)(RALINK_ETH_SW_BASE+0x94) = 0x40ef0001; //VAWD1
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x100) |= 0x2;//VID	LAN->3
#ifdef CONFIG_TP_MODEL_C2V1
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x94) = 0x40e00001; //VAWD1		0110,0000 -> 1110,0000
#elif defined CONFIG_TP_MODEL_C20iV1
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x94) = 0x40de0001; //VAWD1		0101,1110 -> 1101,1110
#endif
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x90) = 0x80001000; //VTCR
	IsSwitchVlanTableBusy();
			
	//*(unsigned long *)(RALINK_ETH_SW_BASE+0x94) = 0x40d00001; //VAWD1
	//*(unsigned long *)(RALINK_ETH_SW_BASE+0x100) = 0x40600001; //VID	WAN->2
#ifdef CONFIG_TP_MODEL_C2V1
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x94) = 0x40d00001; //VAWD1		0101,0000 -> 1101,0000
#elif defined CONFIG_TP_MODEL_C20iV1
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x94) = 0x40c10001; //VAWD1		0100,0001 -> 1100,0001
#endif
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x90) = 0x80001001; //VTCR
	IsSwitchVlanTableBusy();

	//vlanDump();

	return RT_ERR_OK;
}


rtk_api_ret_t rtk_vlan_set(rtk_vlan_t vid, rtk_portmask_t mbrmsk, rtk_portmask_t untagmsk, rtk_fid_t fid)
{
    rtk_api_ret_t retVal;
    rtl8367b_user_vlan4kentry vlan4K;

    /* vid must be 0~4095 */
    if (vid > RTL8367B_VIDMAX)
        return RT_ERR_VLAN_VID;

    if (mbrmsk.bits[0] > RTK_MAX_PORT_MASK)
        return RT_ERR_VLAN_PORT_MBR_EXIST;

    if (untagmsk.bits[0] > RTK_MAX_PORT_MASK)
        return RT_ERR_VLAN_PORT_MBR_EXIST;

    /* fid must be 0~15 */
    if ( (fid != RTK_IVL_MODE_FID) && (fid > RTL8367B_FIDMAX) )
        return RT_ERR_L2_FID;

    /* update 4K table */
    memset(&vlan4K, 0, sizeof(rtl8367b_user_vlan4kentry));
    vlan4K.vid = vid;
    vlan4K.mbr = mbrmsk.bits[0];
    vlan4K.untag = untagmsk.bits[0];

    if(fid == RTK_IVL_MODE_FID)
    {
        vlan4K.ivl_svl  = 1;
        vlan4K.fid_msti = 0;
    }
    else
        vlan4K.fid_msti = fid;

    if ((retVal = rtl8367b_setAsicVlan4kEntry(&vlan4K)) != RT_ERR_OK)
            return retVal;

    return RT_ERR_OK;
}

rtk_api_ret_t rtk_vlan_portPvid_set(rtk_port_t port, rtk_vlan_t pvid, rtk_pri_t priority)
{
    rtk_api_ret_t retVal;
    rtk_int32 i;
    rtk_uint32 j;
    rtk_uint32 k;
    rtk_uint32 index,empty_idx;
    rtk_uint32 gvidx, proc;
    rtk_uint32 bUsed, pri;
    rtl8367b_user_vlan4kentry vlan4K;
    rtl8367b_vlanconfiguser vlanMC;
    rtl8367b_protocolvlancfg ppb_vlan_cfg;

    if (port > RTK_PORT_ID_MAX)
        return RT_ERR_PORT_ID;

    /* vid must be 0~4095 */
    if (pvid > RTL8367B_VIDMAX)
        return RT_ERR_VLAN_VID;

    /* priority must be 0~7 */
    if (priority > RTL8367B_PRIMAX)
        return RT_ERR_VLAN_PRIORITY;


      empty_idx = 0xFFFF;

    for (i = RTL8367B_CVIDXMAX; i >= 0; i--)
    {
        if ((retVal = rtl8367b_getAsicVlanMemberConfig(i, &vlanMC)) != RT_ERR_OK)
            return retVal;

        if (pvid == vlanMC.evid)
        {
            if ((retVal = rtl8367b_setAsicVlanPortBasedVID(port, i, priority)) != RT_ERR_OK)
                return retVal;

            return RT_ERR_OK;
        }
        else if (vlanMC.evid == 0 && vlanMC.mbr == 0)
        {
            empty_idx = i;
        }
    }


    /*
        vid doesn't exist in 32 member configuration. Find an empty entry in
        32 member configuration, then copy entry from 4K. If 32 member configuration
        are all full, then find an entry which not used by Port-based VLAN and
        then replace it with 4K. Finally, assign the index to the port.
    */

    if (empty_idx != 0xFFFF)
    {
        vlan4K.vid = pvid;
        if ((retVal = rtl8367b_getAsicVlan4kEntry(&vlan4K)) != RT_ERR_OK)
            return retVal;

        vlanMC.evid = pvid;
        vlanMC.mbr = vlan4K.mbr;
        vlanMC.fid_msti = vlan4K.fid_msti;
        vlanMC.meteridx= vlan4K.meteridx;
        vlanMC.envlanpol= vlan4K.envlanpol;
        vlanMC.vbpen = vlan4K.vbpen;
        vlanMC.vbpri = vlan4K.vbpri;

        if ((retVal = rtl8367b_setAsicVlanMemberConfig(empty_idx, &vlanMC)) != RT_ERR_OK)
            return retVal;

        if ((retVal = rtl8367b_setAsicVlanPortBasedVID(port,empty_idx, priority)) != RT_ERR_OK)
            return retVal;

        return RT_ERR_OK;
     }

    if ((retVal = rtl8367b_getAsic1xGuestVidx(&gvidx)) != RT_ERR_OK)
        return retVal;

    /* 32 member configuration is full, found a unused entry to replace */
    for (i = 0; i <= RTL8367B_CVIDXMAX; i++)
    {
        bUsed = FALSE;

        for (j = 0; j < RTK_MAX_NUM_OF_PORT; j++)
        {
            if ((retVal = rtl8367b_getAsicVlanPortBasedVID(j, &index, &pri)) != RT_ERR_OK)
                return retVal;

            if (i == index)/*index i is in use by port j*/
            {
                bUsed = TRUE;
                break;
            }

            if (i == gvidx)
            {
                if ((retVal = rtl8367b_getAsic1xProcConfig(j, &proc)) != RT_ERR_OK)
                    return retVal;
                if (DOT1X_UNAUTH_GVLAN == proc )
                {
                    bUsed = TRUE;
                    break;
                }
            }

            for (k = 0; k <= RTL8367B_PROTOVLAN_GIDX_MAX; k++)
            {
                if ((retVal = rtl8367b_getAsicVlanPortAndProtocolBased(port, k, &ppb_vlan_cfg)) != RT_ERR_OK)
                    return retVal;
                if (ppb_vlan_cfg.valid == TRUE && ppb_vlan_cfg.vlan_idx == i)
                {
                    bUsed = TRUE;
                    break;
                }
            }
        }

        if (FALSE == bUsed)/*found a unused index, replace it*/
        {
            vlan4K.vid = pvid;
            if ((retVal = rtl8367b_getAsicVlan4kEntry(&vlan4K)) != RT_ERR_OK)
                return retVal;
            vlanMC.evid = pvid;
            vlanMC.mbr = vlan4K.mbr;
            vlanMC.fid_msti = vlan4K.fid_msti;
            vlanMC.meteridx= vlan4K.meteridx;
            vlanMC.envlanpol= vlan4K.envlanpol;
            vlanMC.vbpen = vlan4K.vbpen;
            vlanMC.vbpri = vlan4K.vbpri;
            if ((retVal = rtl8367b_setAsicVlanMemberConfig(i, &vlanMC)) != RT_ERR_OK)
                return retVal;

            if ((retVal = rtl8367b_setAsicVlanPortBasedVID(port, i, priority)) != RT_ERR_OK)
                return retVal;

            return RT_ERR_OK;
        }
    }

    return RT_ERR_FAILED;
}

ret_t rtl8367b_setAsicLutIpMulticastLookup(rtk_uint32 enabled)
{
	return rtl8367b_setAsicRegBit(RTL8367B_REG_LUT_CFG, RTL8367B_LUT_IPMC_HASH_OFFSET, enabled);
}

ret_t rtl8367b_setAsicLutIpLookupMethod(rtk_uint32 type)
{
	return rtl8367b_setAsicRegBit(RTL8367B_REG_LUT_CFG, RTL8367B_LUT_IPMC_LOOKUP_OP_OFFSET, type);
}

ret_t rtl8367b_setAsicIGMPStaticRouterPort(rtk_uint32 pmsk)
{
    if(pmsk > RTL8367B_PORTMASK)
        return RT_ERR_PORT_MASK;

    return rtl8367b_setAsicRegBits(RTL8367B_REG_IGMP_STATIC_ROUTER_PORT, RTL8367B_IGMP_STATIC_ROUTER_PORT_MASK, pmsk);
}

rtk_api_ret_t rtk_igmp_static_router_port_set(rtk_portmask_t portmask)
{
    rtk_api_ret_t retVal;

    if ( portmask.bits[0] > RTK_MAX_PORT_MASK)
        return RT_ERR_PORT_MASK;

    if ((retVal = rtl8367b_setAsicIGMPStaticRouterPort(portmask.bits[0]))!=RT_ERR_OK)
        return retVal;

    return RT_ERR_OK;
}

void _rtl8367b_fdbStUser2Smi( rtl8367b_luttb *pLutSt, rtl8367b_fdbtb *pFdbSmi)
{
    /*L3 lookup*/
    if(pLutSt->l3lookup)
    {
#if 1//def _LITTLE_ENDIAN
        pFdbSmi->smi_ipmul.sip0         = (pLutSt->sip & 0xFF000000) >> 24;
        pFdbSmi->smi_ipmul.sip1         = (pLutSt->sip & 0x00FF0000) >> 16;
        pFdbSmi->smi_ipmul.sip2         = (pLutSt->sip & 0x0000FF00) >> 8;
        pFdbSmi->smi_ipmul.sip3         = pLutSt->sip & 0x000000FF;

        pFdbSmi->smi_ipmul.dip0         = (pLutSt->dip & 0xFF000000) >> 24;
        pFdbSmi->smi_ipmul.dip1         = (pLutSt->dip & 0x00FF0000) >> 16;
        pFdbSmi->smi_ipmul.dip2         = (pLutSt->dip & 0x0000FF00) >> 8;
        pFdbSmi->smi_ipmul.dip3         = pLutSt->dip & 0x000000FF;
#else
        pFdbSmi->smi_ipmul.sip0         = pLutSt->sip & 0x000000FF;
        pFdbSmi->smi_ipmul.sip1         = (pLutSt->sip & 0x0000FF00) >> 8;
        pFdbSmi->smi_ipmul.sip2         = (pLutSt->sip & 0x00FF0000) >> 16;
        pFdbSmi->smi_ipmul.sip3         = (pLutSt->sip & 0xFF000000) >> 24;

        pFdbSmi->smi_ipmul.dip0         = pLutSt->dip & 0x000000FF;
        pFdbSmi->smi_ipmul.dip1         = (pLutSt->dip & 0x0000FF00) >> 8;
        pFdbSmi->smi_ipmul.dip2         = (pLutSt->dip & 0x00FF0000) >> 16;
        pFdbSmi->smi_ipmul.dip3         = (pLutSt->dip & 0xFF000000) >> 24;
#endif
		pFdbSmi->smi_ipmul.lut_pri 		= pLutSt->lut_pri;
		pFdbSmi->smi_ipmul.fwd_en 		= pLutSt->fwd_en;

		pFdbSmi->smi_ipmul.mbr 			= pLutSt->mbr;
		pFdbSmi->smi_ipmul.igmpidx 		= pLutSt->igmpidx;

        pFdbSmi->smi_ipmul.igmp_asic 	= pLutSt->igmp_asic;
        pFdbSmi->smi_ipmul.l3lookup     = pLutSt->l3lookup;
        pFdbSmi->smi_ipmul.nosalearn    = pLutSt->nosalearn;

        pFdbSmi->smi_ipmul.reserved     = 0;
    }
    /*Multicast L2 Lookup*/
    else if(pLutSt->mac.octet[0] & 0x01)
    {
	 	pFdbSmi->smi_l2mul.mac0         = pLutSt->mac.octet[0];
	 	pFdbSmi->smi_l2mul.mac1         = pLutSt->mac.octet[1];
	 	pFdbSmi->smi_l2mul.mac2         = pLutSt->mac.octet[2];
	 	pFdbSmi->smi_l2mul.mac3         = pLutSt->mac.octet[3];
	 	pFdbSmi->smi_l2mul.mac4         = pLutSt->mac.octet[4];
	 	pFdbSmi->smi_l2mul.mac5         = pLutSt->mac.octet[5];

		pFdbSmi->smi_l2mul.cvid_fid 	= pLutSt->cvid_fid;
		pFdbSmi->smi_l2mul.lut_pri 		= pLutSt->lut_pri;
		pFdbSmi->smi_l2mul.fwd_en 		= pLutSt->fwd_en;

		pFdbSmi->smi_l2mul.mbr 			= pLutSt->mbr;
		pFdbSmi->smi_l2mul.igmpidx 		= pLutSt->igmpidx;

        pFdbSmi->smi_l2mul.igmp_asic 	= pLutSt->igmp_asic;
        pFdbSmi->smi_l2mul.l3lookup     = pLutSt->l3lookup;
        pFdbSmi->smi_l2mul.ivl_svl		= pLutSt->ivl_svl;
        pFdbSmi->smi_l2mul.nosalearn    = pLutSt->nosalearn;

        pFdbSmi->smi_l2mul.reserved     = 0;
    }
    /*Asic auto-learning*/
    else
    {
	 	pFdbSmi->smi_auto.mac0          = pLutSt->mac.octet[0];
	 	pFdbSmi->smi_auto.mac1          = pLutSt->mac.octet[1];
	 	pFdbSmi->smi_auto.mac2          = pLutSt->mac.octet[2];
	 	pFdbSmi->smi_auto.mac3          = pLutSt->mac.octet[3];
	 	pFdbSmi->smi_auto.mac4          = pLutSt->mac.octet[4];
	 	pFdbSmi->smi_auto.mac5          = pLutSt->mac.octet[5];

		pFdbSmi->smi_auto.cvid_fid 		= pLutSt->cvid_fid;
		pFdbSmi->smi_auto.lut_pri 		= pLutSt->lut_pri;
		pFdbSmi->smi_auto.fwd_en 		= pLutSt->fwd_en;
        pFdbSmi->smi_auto.sa_en     	= pLutSt->sa_en;
        pFdbSmi->smi_auto.auth          = pLutSt->auth;;
        pFdbSmi->smi_auto.spa           = pLutSt->spa;
        pFdbSmi->smi_auto.age           = pLutSt->age;
        pFdbSmi->smi_auto.fid           = pLutSt->fid;
        pFdbSmi->smi_auto.efid          = pLutSt->efid;
        pFdbSmi->smi_auto.da_block      = pLutSt->da_block;

		pFdbSmi->smi_auto.sa_block      = pLutSt->sa_block;
        pFdbSmi->smi_auto.l3lookup      = pLutSt->l3lookup;
        pFdbSmi->smi_auto.ivl_svl		= pLutSt->ivl_svl;
        pFdbSmi->smi_auto.nosalearn     = pLutSt->nosalearn;

        pFdbSmi->smi_auto.reserved      = 0;
    }
}

void _rtl8367b_fdbStSmi2User( rtl8367b_luttb *pLutSt, rtl8367b_fdbtb *pFdbSmi)
{
    /*L3 lookup*/
    if(pFdbSmi->smi_ipmul.l3lookup)
    {
		pLutSt->sip            	= pFdbSmi->smi_ipmul.sip0;
		pLutSt->sip            	= (pLutSt->sip << 8) | pFdbSmi->smi_ipmul.sip1;
		pLutSt->sip            	= (pLutSt->sip << 8) | pFdbSmi->smi_ipmul.sip2;
		pLutSt->sip            	= (pLutSt->sip << 8) | pFdbSmi->smi_ipmul.sip3;

#if 1//def _LITTLE_ENDIAN
		pLutSt->dip            	= pFdbSmi->smi_ipmul.dip0;
#else
        pLutSt->dip            	= pFdbSmi->smi_ipmul.dip0 | 0xE0;
#endif
		pLutSt->dip            	= (pLutSt->dip << 8) | pFdbSmi->smi_ipmul.dip1;
		pLutSt->dip            	= (pLutSt->dip << 8) | pFdbSmi->smi_ipmul.dip2;
#if 1//def _LITTLE_ENDIAN
		pLutSt->dip            	= (pLutSt->dip << 8) | pFdbSmi->smi_ipmul.dip3 | 0xE0;
#else
		pLutSt->dip            	= (pLutSt->dip << 8) | pFdbSmi->smi_ipmul.dip3;
#endif
        pLutSt->lut_pri        	= pFdbSmi->smi_ipmul.lut_pri;
        pLutSt->fwd_en         	= pFdbSmi->smi_ipmul.fwd_en;

        pLutSt->mbr          	= pFdbSmi->smi_ipmul.mbr;
        pLutSt->igmpidx        	= pFdbSmi->smi_ipmul.igmpidx;

        pLutSt->igmp_asic      	= pFdbSmi->smi_ipmul.igmp_asic;
        pLutSt->l3lookup       	= pFdbSmi->smi_ipmul.l3lookup;
        pLutSt->nosalearn      	= pFdbSmi->smi_ipmul.nosalearn;
    }
    /*Multicast L2 Lookup*/
    else if(pFdbSmi->smi_l2mul.mac0 & 0x01)
    {
	 	pLutSt->mac.octet[0]   	= pFdbSmi->smi_l2mul.mac0;
	 	pLutSt->mac.octet[1]   	= pFdbSmi->smi_l2mul.mac1;
	 	pLutSt->mac.octet[2]   	= pFdbSmi->smi_l2mul.mac2;
	 	pLutSt->mac.octet[3]   	= pFdbSmi->smi_l2mul.mac3;
	 	pLutSt->mac.octet[4]   	= pFdbSmi->smi_l2mul.mac4;
	 	pLutSt->mac.octet[5]   	= pFdbSmi->smi_l2mul.mac5;

        pLutSt->cvid_fid       	= pFdbSmi->smi_l2mul.cvid_fid;
        pLutSt->lut_pri        	= pFdbSmi->smi_l2mul.lut_pri;
        pLutSt->fwd_en         	= pFdbSmi->smi_l2mul.fwd_en;

        pLutSt->mbr          	= pFdbSmi->smi_l2mul.mbr;
        pLutSt->igmpidx        	= pFdbSmi->smi_l2mul.igmpidx;

        pLutSt->igmp_asic      	= pFdbSmi->smi_l2mul.igmp_asic;
        pLutSt->l3lookup       	= pFdbSmi->smi_l2mul.l3lookup;
        pLutSt->ivl_svl			= pFdbSmi->smi_l2mul.ivl_svl;
        pLutSt->nosalearn      	= pFdbSmi->smi_l2mul.nosalearn;
    }
    /*Asic auto-learning*/
    else
    {
	 	pLutSt->mac.octet[0]   	= pFdbSmi->smi_auto.mac0;
	 	pLutSt->mac.octet[1]   	= pFdbSmi->smi_auto.mac1;
	 	pLutSt->mac.octet[2]   	= pFdbSmi->smi_auto.mac2;
	 	pLutSt->mac.octet[3]   	= pFdbSmi->smi_auto.mac3;
	 	pLutSt->mac.octet[4]   	= pFdbSmi->smi_auto.mac4;
	 	pLutSt->mac.octet[5]   	= pFdbSmi->smi_auto.mac5;

		pLutSt->cvid_fid     	= pFdbSmi->smi_auto.cvid_fid;
		pLutSt->lut_pri     	= pFdbSmi->smi_auto.lut_pri;
		pLutSt->fwd_en     		= pFdbSmi->smi_auto.fwd_en;

		pLutSt->sa_en     		= pFdbSmi->smi_auto.sa_en;
		pLutSt->auth     		= pFdbSmi->smi_auto.auth;
		pLutSt->spa     		= pFdbSmi->smi_auto.spa;
		pLutSt->age     		= pFdbSmi->smi_auto.age;
		pLutSt->fid     		= pFdbSmi->smi_auto.fid;
		pLutSt->efid     		= pFdbSmi->smi_auto.efid;
		pLutSt->da_block     	= pFdbSmi->smi_auto.da_block;

		pLutSt->sa_block     	= pFdbSmi->smi_auto.sa_block;
		pLutSt->l3lookup     	= pFdbSmi->smi_auto.l3lookup;
		pLutSt->ivl_svl			= pFdbSmi->smi_auto.ivl_svl;
		pLutSt->nosalearn     	= pFdbSmi->smi_auto.nosalearn;
    }
}

ret_t rtl8367b_getAsicL2LookupTb(rtk_uint32 method, rtl8367b_luttb *pL2Table)
{
    ret_t retVal;
	rtk_uint32 regData;
	rtk_uint16* accessPtr;
	rtk_uint32 i;
	rtl8367b_fdbtb smil2Table;
	rtk_uint32 busyCounter;
	rtk_uint32 tblCmd;

    if(pL2Table->wait_time == 0)
    	busyCounter = RTL8367B_LUT_BUSY_CHECK_NO;
    else
        busyCounter = pL2Table->wait_time;

 	while(busyCounter)
	{
		retVal = rtl8367b_getAsicRegBit(RTL8367B_TABLE_ACCESS_STATUS_REG, RTL8367B_TABLE_LUT_ADDR_BUSY_FLAG_OFFSET,&regData);
		if(retVal != RT_ERR_OK)
	        return retVal;

		pL2Table->lookup_busy = regData;
		if(!pL2Table->lookup_busy)
			break;

		busyCounter --;
		if(busyCounter == 0)
			return RT_ERR_BUSYWAIT_TIMEOUT;
	}


	tblCmd = (method << RTL8367B_ACCESS_METHOD_OFFSET) & RTL8367B_ACCESS_METHOD_MASK;

	switch(method)
	{
		case LUTREADMETHOD_ADDRESS:
		case LUTREADMETHOD_NEXT_ADDRESS:
		case LUTREADMETHOD_NEXT_L2UC:
		case LUTREADMETHOD_NEXT_L2MC:
		case LUTREADMETHOD_NEXT_L3MC:
		case LUTREADMETHOD_NEXT_L2L3MC:
	        retVal = rtl8367b_setAsicReg(RTL8367B_TABLE_ACCESS_ADDR_REG, pL2Table->address);
	    	if(retVal != RT_ERR_OK)
	    		return retVal;
			break;
		case LUTREADMETHOD_MAC:
	    	memset(&smil2Table, 0x00, sizeof(rtl8367b_fdbtb));
	    	_rtl8367b_fdbStUser2Smi(pL2Table, &smil2Table);

	    	accessPtr =  (rtk_uint16*)&smil2Table;
	    	regData = *accessPtr;
	    	for(i=0; i<RTL8367B_LUT_ENTRY_SIZE; i++)
	    	{
	    		retVal = rtl8367b_setAsicReg(RTL8367B_TABLE_ACCESS_WRDATA_BASE + i, regData);
	    		if(retVal != RT_ERR_OK)
	    			return retVal;

	    		accessPtr ++;
	    		regData = *accessPtr;

	    	}
			break;
		case LUTREADMETHOD_NEXT_L2UCSPA:
	        retVal = rtl8367b_setAsicReg(RTL8367B_TABLE_ACCESS_ADDR_REG, pL2Table->address);
	    	if(retVal != RT_ERR_OK)
	    		return retVal;

			tblCmd = tblCmd | ((pL2Table->spa << RTL8367B_SPA_OFFSET) & RTL8367B_SPA_MASK);

			break;
		default:
			return RT_ERR_INPUT;
	}

	tblCmd = tblCmd | ((RTL8367B_TABLE_ACCESS_REG_DATA(TB_OP_READ,TB_TARGET_L2)) & (RTL8367B_TABLE_TYPE_MASK  | RTL8367B_COMMAND_TYPE_MASK));
	/* Read Command */
	retVal = rtl8367b_setAsicReg(RTL8367B_TABLE_ACCESS_CTRL_REG, tblCmd);
	if(retVal != RT_ERR_OK)
		return retVal;

    if(pL2Table->wait_time == 0)
    	busyCounter = RTL8367B_LUT_BUSY_CHECK_NO;
    else
        busyCounter = pL2Table->wait_time;

	while(busyCounter)
	{
		retVal = rtl8367b_getAsicRegBit(RTL8367B_TABLE_ACCESS_STATUS_REG, RTL8367B_TABLE_LUT_ADDR_BUSY_FLAG_OFFSET,&regData);
		if(retVal != RT_ERR_OK)
	        return retVal;

		pL2Table->lookup_busy = regData;
		if(!pL2Table->lookup_busy)
			break;

		busyCounter --;
		if(busyCounter == 0)
			return RT_ERR_BUSYWAIT_TIMEOUT;
	}

	retVal = rtl8367b_getAsicRegBit(RTL8367B_TABLE_ACCESS_STATUS_REG, RTL8367B_HIT_STATUS_OFFSET,&regData);
	if(retVal != RT_ERR_OK)
        	return retVal;
	pL2Table->lookup_hit = regData;
	if(!pL2Table->lookup_hit)
	{
	    /*Read access address*/
		retVal = rtl8367b_getAsicRegBits(RTL8367B_TABLE_ACCESS_STATUS_REG, RTL8367B_TYPE_MASK | RTL8367B_TABLE_LUT_ADDR_ADDRESS_MASK,&regData);
		if(retVal != RT_ERR_OK)
	        return retVal;

		pL2Table->address = regData;
		
		if(pL2Table->address >= 0x800)
		{
			retVal = rtl8367b_getAsicReg(RTL8367B_TABLE_ACCESS_RDDATA_BASE + 5 , &regData);
			if(retVal != RT_ERR_OK)
				return retVal;
			/*valid bit in CAM is invalid*/
			if(!(regData & 0xFFC0))
			{
				return RT_ERR_L2_ENTRY_NOTFOUND;
			}
			
		}
		else
    			return RT_ERR_L2_ENTRY_NOTFOUND;
	}
    /*Read access address*/
	retVal = rtl8367b_getAsicRegBits(RTL8367B_TABLE_ACCESS_STATUS_REG, RTL8367B_TYPE_MASK | RTL8367B_TABLE_LUT_ADDR_ADDRESS_MASK,&regData);
	if(retVal != RT_ERR_OK)
        return retVal;

    pL2Table->address = regData;

	/*read L2 entry */
   	memset(&smil2Table, 0x00, sizeof(rtl8367b_fdbtb));

	accessPtr = (rtk_uint16*)&smil2Table;

	for(i = 0; i < RTL8367B_LUT_ENTRY_SIZE; i++)
	{
		retVal = rtl8367b_getAsicReg(RTL8367B_TABLE_ACCESS_RDDATA_BASE + i, &regData);
		if(retVal != RT_ERR_OK)
			return retVal;

		*accessPtr = regData;

		accessPtr ++;
	}

	_rtl8367b_fdbStSmi2User(pL2Table, &smil2Table);

	return RT_ERR_OK;
}

rtk_api_ret_t rtk_l2_ipMcastAddr_get(ipaddr_t sip, ipaddr_t dip, rtk_portmask_t *pPortmask)
{
    rtk_api_ret_t retVal;
    rtk_uint32 method;
    rtl8367b_luttb l2Table;

    l2Table.sip = sip;
    l2Table.dip = dip;
    l2Table.l3lookup = 1;
    method = LUTREADMETHOD_MAC;
    if ((retVal = rtl8367b_getAsicL2LookupTb(method, &l2Table)) != RT_ERR_OK)
        return retVal;

     pPortmask->bits[0] = l2Table.mbr;

    return RT_ERR_OK;
}

ret_t rtl8367b_setAsicL2LookupTb(rtl8367b_luttb *pL2Table)
{
	ret_t retVal;
	rtk_uint32 regData;
	rtk_uint16 *accessPtr;
	rtk_uint32 i;
	rtl8367b_fdbtb smil2Table;
	rtk_uint32 tblCmd;
    rtk_uint32 busyCounter;

	memset(&smil2Table, 0x00, sizeof(rtl8367b_fdbtb));
	_rtl8367b_fdbStUser2Smi(pL2Table, &smil2Table);

    if(pL2Table->wait_time == 0)
    	busyCounter = RTL8367B_LUT_BUSY_CHECK_NO;
    else
        busyCounter = pL2Table->wait_time;

    while(busyCounter)
	{
		retVal = rtl8367b_getAsicRegBit(RTL8367B_TABLE_ACCESS_STATUS_REG, RTL8367B_TABLE_LUT_ADDR_BUSY_FLAG_OFFSET,&regData);
		if(retVal != RT_ERR_OK)
	        return retVal;

		pL2Table->lookup_busy = regData;
		if(!regData)
			break;

		busyCounter --;
		if(busyCounter == 0)
			return RT_ERR_BUSYWAIT_TIMEOUT;
	}

	accessPtr =  (rtk_uint16*)&smil2Table;
	regData = *accessPtr;
	for(i = 0; i < RTL8367B_LUT_ENTRY_SIZE; i++)
	{
		retVal = rtl8367b_setAsicReg(RTL8367B_TABLE_ACCESS_WRDATA_BASE + i, regData);
		if(retVal != RT_ERR_OK)
			return retVal;

		accessPtr ++;
		regData = *accessPtr;

	}

	tblCmd = (RTL8367B_TABLE_ACCESS_REG_DATA(TB_OP_WRITE,TB_TARGET_L2)) & (RTL8367B_TABLE_TYPE_MASK  | RTL8367B_COMMAND_TYPE_MASK);
	/* Write Command */
	retVal = rtl8367b_setAsicReg(RTL8367B_TABLE_ACCESS_CTRL_REG, tblCmd);
	if(retVal != RT_ERR_OK)
		return retVal;

    if(pL2Table->wait_time == 0)
    	busyCounter = RTL8367B_LUT_BUSY_CHECK_NO;
    else
        busyCounter = pL2Table->wait_time;

    while(busyCounter)
	{
		retVal = rtl8367b_getAsicRegBit(RTL8367B_TABLE_ACCESS_STATUS_REG, RTL8367B_TABLE_LUT_ADDR_BUSY_FLAG_OFFSET,&regData);
		if(retVal != RT_ERR_OK)
	        return retVal;

		pL2Table->lookup_busy = regData;
		if(!regData)
			break;

		busyCounter --;
		if(busyCounter == 0)
			return RT_ERR_BUSYWAIT_TIMEOUT;
	}

    /*Read access status*/
	retVal = rtl8367b_getAsicRegBit(RTL8367B_TABLE_ACCESS_STATUS_REG, RTL8367B_HIT_STATUS_OFFSET, &regData);
	if(retVal != RT_ERR_OK)
    return retVal;

    pL2Table->lookup_hit = regData;
    if(!pL2Table->lookup_hit)
        return RT_ERR_FAILED;

    /*Read access address*/
	retVal = rtl8367b_getAsicRegBits(RTL8367B_TABLE_ACCESS_STATUS_REG, RTL8367B_TYPE_MASK | RTL8367B_TABLE_LUT_ADDR_ADDRESS_MASK,&regData);
	if(retVal != RT_ERR_OK)
        return retVal;

    pL2Table->address = regData;
	pL2Table->lookup_busy = 0;

	return RT_ERR_OK;
}

rtk_api_ret_t rtk_l2_ipMcastAddr_add(ipaddr_t sip, ipaddr_t dip, rtk_portmask_t portmask)
{
    rtk_api_ret_t retVal;
    rtk_uint32 method;
    rtl8367b_luttb l2Table;

    if (portmask.bits[0]> RTK_MAX_PORT_MASK)
        return RT_ERR_PORT_ID;

    l2Table.sip = sip;
    l2Table.dip = dip;
    l2Table.l3lookup = 1;
    method = LUTREADMETHOD_MAC;
    retVal = rtl8367b_getAsicL2LookupTb(method, &l2Table);
    if (RT_ERR_OK == retVal)
    {
        l2Table.sip = sip;
        l2Table.dip = dip;
        l2Table.mbr= portmask.bits[0];
        l2Table.nosalearn = 1;
        l2Table.l3lookup = 1;
        retVal = rtl8367b_setAsicL2LookupTb(&l2Table);
        return retVal;
    }
    else if (RT_ERR_L2_ENTRY_NOTFOUND == retVal)
    {
        memset(&l2Table, 0, sizeof(rtl8367b_luttb));
        l2Table.sip = sip;
        l2Table.dip = dip;
        l2Table.mbr= portmask.bits[0];
        l2Table.nosalearn = 1;
        l2Table.l3lookup = 1;
        if ((retVal = rtl8367b_setAsicL2LookupTb(&l2Table)) != RT_ERR_OK)
            return retVal;

        method = LUTREADMETHOD_MAC;
        retVal = rtl8367b_getAsicL2LookupTb(method, &l2Table);
        if (RT_ERR_L2_ENTRY_NOTFOUND == retVal)
            return     RT_ERR_L2_INDEXTBL_FULL;
        else
            return retVal;

    }
    else
        return retVal;

}

rtk_api_ret_t rtk_l2_ipMcastAddr_del(ipaddr_t sip, ipaddr_t dip)
{
    rtk_api_ret_t retVal;
    rtk_uint32 method;
    rtl8367b_luttb l2Table;

    l2Table.sip = sip;
    l2Table.dip = dip;
    l2Table.l3lookup = 1;
    method = LUTREADMETHOD_MAC;
    retVal = rtl8367b_getAsicL2LookupTb(method, &l2Table);
    if (RT_ERR_OK == retVal)
    {
        l2Table.sip = sip;
        l2Table.dip = dip;
        l2Table.mbr= 0;
        l2Table.nosalearn = 0;
        l2Table.l3lookup = 1;
        retVal = rtl8367b_setAsicL2LookupTb(&l2Table);
        return retVal;
    }
    else
        return retVal;
}

rtk_api_ret_t rtk_l2_ipMcastAddrLookup_set(rtk_l2_lookup_type_t type)
{
    rtk_api_ret_t retVal;

    if(type == LOOKUP_MAC)
    {
        if((retVal = rtl8367b_setAsicLutIpMulticastLookup(DISABLED)) != RT_ERR_OK)
            return retVal;
    }
    else if(type == LOOKUP_SIP_DIP)
    {
    if ((retVal = rtl8367b_setAsicLutIpMulticastLookup(ENABLED))!=RT_ERR_OK)
        return retVal;

        if ((retVal = rtl8367b_setAsicLutIpLookupMethod(0))!=RT_ERR_OK)
            return retVal;
    }
    else if(type == LOOKUP_DIP)
    {
        if((retVal = rtl8367b_setAsicLutIpMulticastLookup(ENABLED)) != RT_ERR_OK)
        return retVal;

        if ((retVal = rtl8367b_setAsicLutIpLookupMethod(1))!=RT_ERR_OK)
        return retVal;
    }
    else
        return RT_ERR_FAILED;

    return RT_ERR_OK;
}

rtk_api_ret_t rtk_l2_addr_get(rtk_mac_t *pMac, rtk_l2_ucastAddr_t *pL2_data)
{
    rtk_api_ret_t retVal;
    rtk_uint32 method;
    rtl8367b_luttb l2Table;

    /* must be unicast address */
    if ((pMac == NULL) || (pMac->octet[0] & 0x1))
        return RT_ERR_MAC;

    if (pL2_data->fid > RTL8367B_FIDMAX || pL2_data->efid > RTL8367B_EFIDMAX)
        return RT_ERR_L2_FID;

    memset(&l2Table, 0, sizeof(rtl8367b_luttb));

    memcpy(l2Table.mac.octet, pMac->octet, ETHER_ADDR_LEN);
    l2Table.ivl_svl     = pL2_data->ivl;
    l2Table.cvid_fid    = pL2_data->cvid;
    l2Table.fid         = pL2_data->fid;
    l2Table.efid        = pL2_data->efid;
    method = LUTREADMETHOD_MAC;

    if ((retVal = rtl8367b_getAsicL2LookupTb(method, &l2Table)) != RT_ERR_OK)
        return retVal;

    memcpy(pL2_data->mac.octet, pMac->octet,ETHER_ADDR_LEN);
    pL2_data->port      = l2Table.spa;
    pL2_data->fid       = l2Table.fid;
    pL2_data->efid      = l2Table.efid;
    pL2_data->ivl       = l2Table.ivl_svl;
    pL2_data->cvid      = l2Table.cvid_fid;
    pL2_data->is_static = l2Table.nosalearn;
    pL2_data->auth      = l2Table.auth;
    pL2_data->sa_block  = l2Table.sa_block;
    pL2_data->da_block  = l2Table.da_block;

    return RT_ERR_OK;
}

static void reg_read(int offset, int *value)
{
	*value = (*((volatile u32 *)(RALINK_ETH_SW_BASE + offset)));
}

static void reg_write(int offset, int value)
{
	(*((volatile u32 *)(RALINK_ETH_SW_BASE + offset))) = value;
}

rtk_api_ret_t mtk_l2_ipMcastAddr_add(unsigned int ip_addr, unsigned char portmsk)
{
	unsigned int index, value;
	
	value = ntohl(ip_addr);
	reg_write(REG_ESW_WT_MAC_ATA1, value);
	RTL8367_DEBUG("ip_addr is 0x%x\n\r",value);

	value = portmsk << 4; //w_port_map
	value |= (0x3<< 2); //static  (0x01<< 2);//

	reg_write(REG_ESW_WT_MAC_ATWD, value);
	
	udelay(5000);
	reg_read(REG_ESW_WT_MAC_ATWD, &value);

       value = 0x8011;  //single w_dip_cmd
	reg_write(REG_ESW_WT_MAC_ATC, value);

	udelay(1000);
	for (index = 0; index < 20; index++) 
	{
		reg_read(REG_ESW_WT_MAC_ATC, &value);
		if ((value & 0x8000) == 0 )//mac address busy
		{ 
			RTL8367_DEBUG("add ipMulCastRule done.\n");
			return RT_ERR_OK;
		}
		udelay(1000);
	}
	
	if (index == 20)
	{
		RTL8367_ERROR("add ipMulCastRule timeout.\n");
		return RT_ERR_BUSYWAIT_TIMEOUT;
	}

	return RT_ERR_OK;
}

rtk_api_ret_t mtk_l2_ipMcastAddr_del(unsigned int ip_addr)
{
	unsigned int index, value;

	value = ntohl(ip_addr);
	reg_write(REG_ESW_WT_MAC_ATA1, value);

	value = 0;
	reg_write(REG_ESW_WT_MAC_ATA2, value);

	value = 0; //STATUS=0, delete dip
	reg_write(REG_ESW_WT_MAC_ATWD, value);

       value = 0x8011;  //w_dip_cmd
	reg_write(REG_ESW_WT_MAC_ATC, value);

	for (index = 0; index < 20; index++) 
	{
		reg_read(REG_ESW_WT_MAC_ATC, &value);
		if ((value & 0x8000) == 0 )//mac address busy
		{ 
			RTL8367_DEBUG("del ipMulCastRule done.\n");
			return RT_ERR_OK;
		}
		udelay(1000);
	}
	
	if (index == 20)
	{
		RTL8367_ERROR("del ipMulCastRule timeout.\n");
		return RT_ERR_BUSYWAIT_TIMEOUT;
	}
	
	return RT_ERR_OK;
}

rtk_api_ret_t mtk_l2_ipMcastAddr_get(unsigned int ip_addr, unsigned char *portMsk)
{
	int index, mac, value, value2;

	reg_write(REG_ESW_WT_MAC_ATC, 0x8104);//dip search command
	udelay(5000);
	for (index = 0; index < 0x800; index++) 
	{
		while(1) 
		{
			reg_read(REG_ESW_WT_MAC_ATC, &value);

			if (value & (0x1 << 13))  //search_rdy
			{
				reg_read(REG_ESW_TABLE_TSRA1, &mac);
				RTL8367_DEBUG("mac is 0x%x	ip_addr is 0x%x\n", mac, ntohl(ip_addr));
				if (mac != ntohl(ip_addr))
				{
					break;
				}
				
				reg_read(REG_ESW_TABLE_ATRD, &value2);
				*portMsk = (value2 >> 4) & 0xff; //r_port_map
				RTL8367_DEBUG("portMsk is 0x%x\n", *portMsk);
				
				return RT_ERR_OK;
			}
			else if (value & 0x4000) //at_table_end
			{
				RTL8367_DEBUG("found the last entry %d (not ready)\n", index);
				return RT_ERR_L2_ENTRY_NOTFOUND;
			}
			udelay(5000);
		}
		reg_write(REG_ESW_WT_MAC_ATC, 0x8105); //search for next dip address
		udelay(5000);
	}

	return RT_ERR_L2_ENTRY_NOTFOUND;
}

rtk_api_ret_t mtk_l2_addr_get(unsigned char *pMac, unsigned char *portMsk)
{
	int index, value, mac, mac2, value2;
	unsigned char tempMac[6];

	RTL8367_DEBUG("pMac is %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X\n", pMac[0], pMac[1],
					pMac[2], pMac[3], pMac[4], pMac[5]);

	reg_write(REG_ESW_WT_MAC_ATC, 0x8004);
	udelay(5000);
	for (index = 0; index < 0x800; index++) 
	{
		while(1) 
		{
			reg_read(REG_ESW_WT_MAC_ATC, &value);
			
			if (value & (0x1 << 13))  //search_rdy
			{
				reg_read(REG_ESW_TABLE_TSRA1, &mac);
				reg_read(REG_ESW_TABLE_TSRA2, &mac2);

				tempMac[3] = mac & 0xff;
				tempMac[2] = (mac >> 8) & 0xff;
				tempMac[1] = (mac >> 16) & 0xff;
				tempMac[0] = (mac >> 24) & 0xff;
				tempMac[5] = ((mac2 >> 16) & 0xffff) & 0xff;
				tempMac[4] = (((mac2 >> 16) & 0xffff) >> 8) & 0xff;
				RTL8367_DEBUG("tempMac is %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X\n", tempMac[0], tempMac[1],
					tempMac[2], tempMac[3], tempMac[4], tempMac[5]);
				if (!(tempMac[0] == pMac[0] && tempMac[1] == pMac[1]
					&& tempMac[2] == pMac[2] && tempMac[3] == pMac[3]
					&& tempMac[4] == pMac[4] && tempMac[5] == pMac[5]))//(strcmp(tempMac, pMac) != 0)
				{
					break;
				}
				
				reg_read(REG_ESW_TABLE_ATRD, &value2);
				*portMsk = (value2 >> 4) & 0xff; //r_port_map
				RTL8367_DEBUG("portMsk is 0x%x\n", *portMsk);
				
				return RT_ERR_OK;
			}
			else if (value & 0x4000)  //at_table_end
			{
				RTL8367_DEBUG("found the last entry %d (not ready)\n", index);
				return RT_ERR_L2_ENTRY_NOTFOUND;
			}
			udelay(5000);
		}
		reg_write(REG_ESW_WT_MAC_ATC, 0x8005); //search for next address
		udelay(5000);
	}
	
	return RT_ERR_L2_ENTRY_NOTFOUND;
}

/**************************************************************************************************/
/*                                           PUBLIC_FUNCTIONS                                     */
/**************************************************************************************************/
/* Port from Realtek */
u32 rtl_smi_write(u32 mAddrs, u32 rData)
{
	u32 count = 0;
	//RTL8367_DEBUG("About write 0x%x to 0x%x\n", rData, mAddrs);
	/* Write Start command to register 29 */
	mii_mgr_write(MDC_MDIO_DUMMY_ID, MDC_MDIO_START_REG, MDC_MDIO_START_OP);

	/* Write address control code to register 31 */
	mii_mgr_write(MDC_MDIO_DUMMY_ID, MDC_MDIO_CTRL0_REG, MDC_MDIO_ADDR_OP);

	/* Write Start command to register 29 */
	mii_mgr_write(MDC_MDIO_DUMMY_ID, MDC_MDIO_START_REG, MDC_MDIO_START_OP);
	
	/* Write address to register 23 */
	mii_mgr_write(MDC_MDIO_DUMMY_ID, MDC_MDIO_ADDRESS_REG, mAddrs);
	{
		u32 regData;
        count = 0;
		do
		{
			mii_mgr_read(MDC_MDIO_DUMMY_ID, MDC_MDIO_ADDRESS_REG, &regData);
			if (regData != mAddrs)
			{
				if (count++ > 10)
                {
                	goto smi_fail;
                }
				RTL8367_DEBUG("23 write operation error...	write:0x%x	read:0x%x\n", mAddrs, regData);
				mii_mgr_write(MDC_MDIO_DUMMY_ID, MDC_MDIO_ADDRESS_REG, mAddrs);
			}
		}while(regData != mAddrs);
	}

	/* Write Start command to register 29 */
	mii_mgr_write(MDC_MDIO_DUMMY_ID, MDC_MDIO_START_REG, MDC_MDIO_START_OP);

	/* Write data to register 24 */
	mii_mgr_write(MDC_MDIO_DUMMY_ID, MDC_MDIO_DATA_WRITE_REG, rData);
	{
		u32 regData;
        count = 0;
		do
		{
			mii_mgr_read(MDC_MDIO_DUMMY_ID, MDC_MDIO_DATA_WRITE_REG, &regData);
			if (regData != rData)
			{
				if (count++ > 10)
                {
                	goto smi_fail;
                }
				RTL8367_DEBUG("24 write operation error...	write:0x%x	read:0x%x\n", rData, regData);
				mii_mgr_write(MDC_MDIO_DUMMY_ID, MDC_MDIO_DATA_WRITE_REG, rData);
			}
		}while(regData != rData);
	}

	/* Write Start command to register 29 */
	mii_mgr_write(MDC_MDIO_DUMMY_ID, MDC_MDIO_START_REG, MDC_MDIO_START_OP);

	/* Write Start control code to register 21 */
	mii_mgr_write(MDC_MDIO_DUMMY_ID, MDC_MDIO_CTRL1_REG, MDC_MDIO_WRITE_OP);
	{
		u32 regData;
        count = 0;
		do
		{
			mii_mgr_read(MDC_MDIO_DUMMY_ID, MDC_MDIO_CTRL1_REG, &regData);
			if (regData != MDC_MDIO_WRITE_OP - 1)
			{
				if (count++ > 10)
                {
                	goto smi_fail;
                }
				RTL8367_DEBUG("21 write operation error...	write:0x2		read:0x%x\n", regData);
				mii_mgr_write(MDC_MDIO_DUMMY_ID, MDC_MDIO_CTRL1_REG, MDC_MDIO_WRITE_OP);
			}
		}while(regData != MDC_MDIO_WRITE_OP - 1);
	}

	return 0;
smi_fail:
    return 1;
}

u32 rtl_smi_read(u32 mAddrs, u32* rData)
{
	u32 count = 0;
	//RTL8367_DEBUG("Try to read at 0x%x\n", mAddrs);
	/* Write Start command to register 29 */
	mii_mgr_write(MDC_MDIO_DUMMY_ID, MDC_MDIO_START_REG, MDC_MDIO_START_OP);

	/* Write address control code to register 31 */
	mii_mgr_write(MDC_MDIO_DUMMY_ID, MDC_MDIO_CTRL0_REG, MDC_MDIO_ADDR_OP);

	/* Write Start command to register 29 */
	mii_mgr_write(MDC_MDIO_DUMMY_ID, MDC_MDIO_START_REG, MDC_MDIO_START_OP);

	/* Write address to register 23 */
	mii_mgr_write(MDC_MDIO_DUMMY_ID, MDC_MDIO_ADDRESS_REG, mAddrs);
	{
		u32 regData;
        count = 0;
		do
		{
			mii_mgr_read(MDC_MDIO_DUMMY_ID, MDC_MDIO_ADDRESS_REG, &regData);
			if (regData != mAddrs)
			{
				if (count++ > 10)
                {
                	goto smi_fail;
                }
				RTL8367_DEBUG("23 write operation error...	write:0x%x	read:0x%x\n", mAddrs, regData);
				mii_mgr_write(MDC_MDIO_DUMMY_ID, MDC_MDIO_ADDRESS_REG, mAddrs);
			}
		}while(regData != mAddrs);
	}

	/* Write Start command to register 29 */
	mii_mgr_write(MDC_MDIO_DUMMY_ID, MDC_MDIO_START_REG, MDC_MDIO_START_OP);

	/* Write read control code to register 21 */
	mii_mgr_write(MDC_MDIO_DUMMY_ID, MDC_MDIO_CTRL1_REG, MDC_MDIO_READ_OP);
	{
		u32 regData;
        count = 0;
		do
		{
			mii_mgr_read(MDC_MDIO_DUMMY_ID, MDC_MDIO_CTRL1_REG, &regData);
			if (regData != MDC_MDIO_READ_OP - 1)
			{
				if (count++ > 10)
                {
                	goto smi_fail;
                }
				RTL8367_DEBUG("21 read operation error...	write:0x0		read:0x%x\n", regData);
				mii_mgr_write(MDC_MDIO_DUMMY_ID, MDC_MDIO_CTRL1_REG, MDC_MDIO_READ_OP);
			}
		}while(regData != MDC_MDIO_READ_OP - 1);
	}

	/* Write Start command to register 29 */
	mii_mgr_write(MDC_MDIO_DUMMY_ID, MDC_MDIO_START_REG, MDC_MDIO_START_OP);

	/* Read data from register 25 */
	if (1 != mii_mgr_read(MDC_MDIO_DUMMY_ID, MDC_MDIO_DATA_READ_REG, rData))
	{
		RTL8367_DEBUG("mii_mgr_read error\n");
		return 1;
	}
	count= 0;
	while (*rData == 0xffff)
	{
		if (count++ > 10)
        {
        	goto smi_fail;
        }
		RTL8367_DEBUG("25 is 0xffff\n");
		mii_mgr_read(MDC_MDIO_DUMMY_ID, MDC_MDIO_DATA_READ_REG, rData);
	}
	//RTL8367_DEBUG("Reg 0x%x with data 0x%x\n", mAddrs, *rData);
	return 0;
smi_fail:
    return 1;
}
/* For C2 port1~3 is LAN */
int rt_rt8367_chkLan(void)
{
	u32 regData = 0;
	int count = 0;
	int ret = -1;

	for (count = 1; count <= 4; count++)
	{
		rtl_smi_read(RTL8367_PORT0_STATUS_REG + count, &regData);
		if (regData & 0x10)
		{
			ret = 0;
			break;
		}
	}
	return ret;
}

/* For C2 port0 is WAN */
int rt_rt8367_chkWan(void)
{
	u32 regData = 0;

	rtl_smi_read(RTL8367_PORT0_STATUS_REG, &regData);
	if (regData & 0x10)
	{
		return 0;
	}
	return -1;
}

void rt_rtl8367_phy_status(void)
{
#if 1
#else
	u32 regData = 0;
	int count = 0;
	rtl_smi_read(RTL8367_EXTINTF_CTRL_REG, &regData);
	printf("RTL8367_EXTINTF_CTRL_REG is 0x%x\n", regData);

	for (count = 0; count <= 7; count++)
	{
		regData = 0;
		rtl_smi_read(RTL8367_PORT0_STATUS_REG + count, &regData);
		printf("RTL8367_PORT_STATUS_REG(%d) is 0x%x\n", count, regData);
	}
#endif
	
}
/* 
 * According to <RTL8367RB_Switch_ProgrammingGuide> 4.14 Force External Interface 
 * For RTL8367RB, MAC6 <---> RG1(Port1) and MAC7 <---> RG2(Port2)
 */
void rt_rtl8367_enableRgmii(void)
{
	RTL8367_DEBUG("Call Func rt_rtl8367_enableRgmii()\n");
#if 1
	/* 
	 * 1. rtl8367b_setAsicPortExtMode
	 * (EXT_PORT_1, MODE_EXT_RGMII)
	 * (EXT_PORT_2, MODE_EXT_RGMII)
	 */
#ifdef ENABLE_PORT_6
	rtl8367b_setAsicRegBit(RTL8367B_REG_BYPASS_LINE_RATE, EXT_PORT_1, 0);
	rtl8367b_setAsicRegBits(RTL8367B_REG_DIGITAL_INTERFACE_SELECT, 0xF << (EXT_PORT_1 * RTL8367B_SELECT_GMII_1_OFFSET), MODE_EXT_RGMII);
#endif

#ifdef ENABLE_PORT_7
	rtl8367b_setAsicRegBit(RTL8367B_REG_BYPASS_LINE_RATE, EXT_PORT_2, 0);
	rtl8367b_setAsicRegBits(RTL8367B_REG_DIGITAL_INTERFACE_SELECT_1, 0xF, MODE_EXT_RGMII);
#endif


	/* 2. rtl8367b_getAsicPortForceLinkExt */
	/* 3. rtl8367b_setAsicPortForceLinkExt */
#ifdef ENABLE_PORT_6/* enable RTL8367 port 7 witch RGMII  */
	{
		u32 reg_data;
		//rtl8367b_port_ability_t *pExtPort1 = (u16*)&reg_data;

		rtl_smi_read(RTL8367B_REG_DIGITAL_INTERFACE1_FORCE, &reg_data);

		reg_data &= ~0x10f7;
		reg_data |= ((1<<12) | (2 << 0) | (1 << 2) | (7 << 4));
		
		/*pExtPort1->forcemode = 1;
		pExtPort1->speed = 2;
		pExtPort1->duplex = 1;
		pExtPort1->link = 1;
		pExtPort1->nway = 0;
		pExtPort1->txpause = 1;
		pExtPort1->rxpause = 1;*/

		rtl_smi_write(RTL8367B_REG_DIGITAL_INTERFACE1_FORCE, reg_data);
	}
#endif
#ifdef ENABLE_PORT_7/* enable RTL8367 port 7 witch RGMII  */
	{
		u32 reg_data;
		//rtl8367b_port_ability_t *pExtPort1 = (u16*)&reg_data;

		rtl_smi_read(RTL8367B_REG_DIGITAL_INTERFACE2_FORCE, &reg_data);

		reg_data &= ~0x10f7;
		reg_data |= ((1<<12) | (2 << 0) | (1 << 2) | (7 << 4));
		
		/*pExtPort1->forcemode = 1;
		pExtPort1->speed = 2;
		pExtPort1->duplex = 1;
		pExtPort1->link = 1;
		pExtPort1->nway = 0;
		pExtPort1->txpause = 1;
		pExtPort1->rxpause = 1;*/
		
		rtl_smi_write(RTL8367B_REG_DIGITAL_INTERFACE2_FORCE, reg_data);
	}
	#endif
	
#else
	u32 regData = 0;
	regData = (0x1 << 0) | (0x1 << 4);
	rtl_smi_write(RTL8367_EXTINTF_CTRL_REG, regData);
	printf("%s, %d, 0x%x\n", __FUNCTION__, __LINE__, regData);
	rtl_smi_read(RTL8367_EXTINTF_CTRL_REG, &regData);
	printf("%s, %d, 0x%x\n", __FUNCTION__, __LINE__, regData);
#endif
}

/* Function Name:
 *      rtk_switch_init
 * Description:
 *      Set chip to default configuration enviroment
 * Input:
 *      None
 * Output:
 *      None
 * Return:
 *      RT_ERR_OK           - OK
 *      RT_ERR_FAILED       - Failed
 *      RT_ERR_SMI          - SMI access error
 * Note:
 *      The API can set chip registers to default configuration for different release chip model.
 */
rtk_api_ret_t rtk_switch_init(void)
{
    rtk_uint16      i;
    rtk_uint32      data;
    rtk_api_ret_t   retVal;
    rtk_uint32      phy;

    if((retVal = rtl8367b_setAsicReg(0x13C2, 0x0249)) != RT_ERR_OK)
        return retVal;

    if((retVal = rtl8367b_getAsicReg(0x1301, &data)) != RT_ERR_OK)
        return retVal;

    if(data & 0xF000)
    {
        init_para = ChipData31;
        init_size = (sizeof(ChipData31) / ((sizeof(rtk_uint16))*2));
    }
    else
    {
        init_para = ChipData30;
        init_size = (sizeof(ChipData30) / ((sizeof(rtk_uint16))*2));
    }

    if(init_para == NULL)
        return RT_ERR_CHIP_NOT_SUPPORTED;

    /* Analog parameter update. ID:0001 */
    for(phy = 0; phy <= RTK_PHY_ID_MAX; phy++)
    {
        if((retVal = rtl8367b_setAsicPHYReg(phy, 31, 0x7)) != RT_ERR_OK)
            return retVal;

        if((retVal = rtl8367b_setAsicPHYReg(phy, 30, 0x2c)) != RT_ERR_OK)
            return retVal;

        if((retVal = rtl8367b_setAsicPHYReg(phy, 25, 0x0504)) != RT_ERR_OK)
            return retVal;

        if((retVal = rtl8367b_setAsicPHYReg(phy, 31, 0x0)) != RT_ERR_OK)
            return retVal;
    }

    for(i = 0; i < init_size; i++)
    {
        if((retVal = _rtk_switch_init_setreg((rtk_uint32)init_para[i][0], (rtk_uint32)init_para[i][1])) != RT_ERR_OK)
            return retVal;
    }

    /* Analog parameter update. ID:0002 */
    if((retVal = rtl8367b_setAsicPHYReg(1, 31, 0x2)) != RT_ERR_OK)
        return retVal;

    if((retVal = rtl8367b_getAsicPHYReg(1, 17, &data)) != RT_ERR_OK)
        return retVal;

    data |= 0x01E0;

    if((retVal = rtl8367b_setAsicPHYReg(1, 17, data)) != RT_ERR_OK)
        return retVal;

    if((retVal = rtl8367b_setAsicPHYReg(1, 31, 0x0)) != RT_ERR_OK)
        return retVal;


    if((retVal = rtl8367b_setAsicRegBit(0x18e0, 0, 0)) != RT_ERR_OK)
        return retVal;

    if((retVal = rtl8367b_setAsicReg(0x1303, 0x0778)) != RT_ERR_OK)
        return retVal;
    if((retVal = rtl8367b_setAsicReg(0x1304, 0x7777)) != RT_ERR_OK)
        return retVal;
    if((retVal = rtl8367b_setAsicReg(0x13E2, 0x01FE)) != RT_ERR_OK)
        return retVal;

    return RT_ERR_OK;
}

rtk_api_ret_t rt_rtl8367_initVlan()
{
	RTL8367_DEBUG("Call Func rt_rtl8367_initVlan()\n");
	#if 0
	u32 index = 0;
	u32 page_index = 0;
	/* clean 32 VLAN member configuration */
	for (index = 0; index <= RTL8367B_CVIDXMAX; index++)
	{
		for (page_index = 0; page_index < 4; page_index++)
		{
			rtl_smi_write(RTL8367B_VLAN_MEMBER_CONFIGURATION_BASE + (index * 4) + page_index, 0x0);
		}
	}

	/* Set a default VLAN with vid 1 to 4K table for all ports */
	/* 1. Prepare Data */
	rtl_smi_write(RTL8367B_TABLE_ACCESS_WRDATA_BASE, 0xffff);
	rtl_smi_write(RTL8367B_TABLE_ACCESS_WRDATA_BASE + 1, 0x0);
	/* 2. Write Address (VLAN_ID) */
	rtl_smi_write(RTL8367B_TABLE_ACCESS_ADDR_REG, 0x1);/* vid=1 */
	/* 3. Write Command */
	rtl_smi_write(RTL8367B_TABLE_ACCESS_CTRL_REG, (1 << 3) | (3 << 0));

	/* Also set the default VLAN to 32 member configuration index 0 */
	rtl_smi_write(RTL8367B_VLAN_MEMBER_CONFIGURATION_BASE, 0xff);
	rtl_smi_write(RTL8367B_VLAN_MEMBER_CONFIGURATION_BASE + 1, 0x0);
	rtl_smi_write(RTL8367B_VLAN_MEMBER_CONFIGURATION_BASE + 2, 0x0);
	rtl_smi_write(RTL8367B_VLAN_MEMBER_CONFIGURATION_BASE + 3, 0x1);

	/* Set all ports PVID to default VLAN and tag-mode to original */
	/* 1. Port base vid */
	rtl_smi_write(RTL8367B_VLAN_PVID_CTRL_BASE, 0x0);
	rtl_smi_write(RTL8367B_VLAN_PVID_CTRL_BASE + 1, 0x0);
	rtl_smi_write(RTL8367B_VLAN_PVID_CTRL_BASE + 2, 0x0);
	rtl_smi_write(RTL8367B_VLAN_PVID_CTRL_BASE + 3, 0x0);
	rtl_smi_write(RTL8367B_VLAN_PORTBASED_PRIORITY_BASE, 0x0);
	rtl_smi_write(RTL8367B_VLAN_PORTBASED_PRIORITY_BASE + 1, 0x0);
	/* 2. Egress Tag Mode */
	for (index = 0; index < 8; index++)
	{
		rtl8367b_setAsicRegBits(RTL8367B_PORT_MISC_CFG_BASE + (index << 5), 0x30, 0x0);
	}

	/* Enable VLAN */
	rtl_smi_write(RTL8367B_REG_VLAN_CTRL, 0x1);

	#endif
	
	rtk_api_ret_t retVal;
       rtk_uint32 i;
       rtl8367b_user_vlan4kentry vlan4K;
       rtl8367b_vlanconfiguser vlanMC;
   
   
       /* clean 32 VLAN member configuration */
       for (i = 0; i <= RTL8367B_CVIDXMAX; i++)
       {
           vlanMC.evid = 0;
           vlanMC.mbr = 0;
           vlanMC.fid_msti = 0;
           vlanMC.envlanpol = 0;
           vlanMC.meteridx = 0;
           vlanMC.vbpen = 0;
           vlanMC.vbpri = 0;
           if ((retVal = rtl8367b_setAsicVlanMemberConfig(i, &vlanMC)) != RT_ERR_OK)
               return retVal;
       }
   
       /* Set a default VLAN with vid 1 to 4K table for all ports */
       memset(&vlan4K, 0, sizeof(rtl8367b_user_vlan4kentry));
       vlan4K.vid = 1;
       vlan4K.mbr = RTK_MAX_PORT_MASK;
       vlan4K.untag = RTK_MAX_PORT_MASK;
       vlan4K.fid_msti = 0;
       if ((retVal = rtl8367b_setAsicVlan4kEntry(&vlan4K)) != RT_ERR_OK)
           return retVal;
   
   
       /* Also set the default VLAN to 32 member configuration index 0 */
       memset(&vlanMC, 0, sizeof(rtl8367b_vlanconfiguser));
       vlanMC.evid = 1;
       vlanMC.mbr = RTK_MAX_PORT_MASK;
       vlanMC.fid_msti = 0;
       if ((retVal = rtl8367b_setAsicVlanMemberConfig(0, &vlanMC)) != RT_ERR_OK)
               return retVal;
   
       /* Set all ports PVID to default VLAN and tag-mode to original */
       for (i = 0; i < RTK_MAX_NUM_OF_PORT; i++)
       {
           if ((retVal = rtl8367b_setAsicVlanPortBasedVID(i, 0, 0)) != RT_ERR_OK)
               return retVal;
           if ((retVal = rtl8367b_setAsicVlanEgressTagMode(i, EG_TAG_MODE_ORI)) != RT_ERR_OK)
               return retVal;
       }
   
       /* enable VLAN */
       if ((retVal = rtl8367b_setAsicVlanFilter(TRUE)) != RT_ERR_OK)
           return retVal;
   
       return RT_ERR_OK;
}

void rt_rtl8367_stat_port_save(u32 port)
{
	
	/* address offset to MIBs counter */
	const u16 mibLength[RTL8367B_MIBS_NUMBER]= {
		4,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
		4,2,2,2,2,2,2,2,2,
		4,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
		2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2};

	u32 mibAddr;
	u32 mibOff=0;
	u32 index = 0;
	u32 regData = 0;
	u32 mibCounterIn = 0;
	u32 mibCounterOut = 0;
	u32 regAddr = 0;

	if (port > 7)
	{
		return;
	}

	/* ifInOctets */

	index = 0;
	mibOff = RTL8367B_MIB_PORT_OFFSET * port;

	while(index < ifInOctets)
	{
		mibOff += mibLength[index];
		index++;
	}
	/*RTL8367_DEBUG("mibOff is 0x%x\n", mibOff);*/
	
	mibAddr = mibOff;

	/*RTL8367_DEBUG("Write 0x%x to 0x%x\n", (mibAddr >> 2), RTL8367B_REG_MIB_ADDRESS);*/

	rtl_smi_write(RTL8367B_REG_MIB_ADDRESS, (mibAddr >> 2));

	 /* polling busy flag */
    index = 100;
    while (index > 0)
    {
        /*read MIB control register*/
        rtl_smi_read(RTL8367B_MIB_CTRL_REG,&regData);
    
        if ((regData & 0x1) == 0)
        {
            break;
        }
    
        index--;
    }
	if (regData & 0x1)
	{
		RTL8367_DEBUG("MIB BUSYWAIT_TIMEOUT\n");
		return ;
	}
	if (regData & 0x2)
	{
		RTL8367_DEBUG("MIB STAT_CNTR_FAIL\n");
		return ;
	}

	
#if 0
	index = mibLength[ifInOctets];
	if(4 == index)
		regAddr = RTL8367B_REG_MIB_COUNTER0 + 3;
	else
		regAddr = RTL8367B_REG_MIB_COUNTER0 + ((mibOff + 1) % 4);

	regData = 0;
	mibCounterIn = 0;
	while(index)
	{
		rtl_smi_read(regAddr, &regData);
		RTL8367_DEBUG("Read from 0x%x is 0x%x \n", regAddr, regData);
		mibCounterIn = (mibCounterIn << 16) | (regData & 0xFFFF);
		/*RTL8367_DEBUG("mibCounterIn 0x%x \n", mibCounterIn);*/

		regAddr--;
		index--;
	}
#else
	mibCounterIn = 0;

	rtl_smi_read(RTL8367B_REG_MIB_COUNTER0 + 1, &regData);
	mibCounterIn = (regData & 0xFFFF);

	rtl_smi_read(RTL8367B_REG_MIB_COUNTER0, &regData);
	mibCounterIn = (mibCounterIn << 16) | (regData & 0xFFFF);

#endif
	/* ifOutOctets */

	index = 0;
	mibOff = RTL8367B_MIB_PORT_OFFSET * port;

	while(index < ifOutOctets)/*ifInOctets*/
	{
		mibOff += mibLength[index];
		index++;
	}		
	/*RTL8367_DEBUG("mibOff is 0x%x\n", mibOff);*/
	
	mibAddr = mibOff;

	/*RTL8367_DEBUG("Write 0x%x to 0x%x\n", (mibAddr >> 2), RTL8367B_REG_MIB_ADDRESS);*/

	rtl_smi_write(RTL8367B_REG_MIB_ADDRESS, (mibAddr >> 2));

	 /* polling busy flag */
    index = 100;
    while (index > 0)
    {
        /*read MIB control register*/
        rtl_smi_read(RTL8367B_MIB_CTRL_REG, &regData);
    
        if ((regData & 0x1) == 0)
        {
            break;
        }
    
        index--;
    }
	if (regData & 0x1)
	{
		RTL8367_DEBUG("MIB BUSYWAIT_TIMEOUT\n");
		return ;
	}
	if (regData & 0x2)
	{
		RTL8367_DEBUG("MIB STAT_CNTR_FAIL\n");
		return ;
	}

	
#if 0
	index = mibLength[ifOutOctets];
	if(4 == index)
		regAddr = RTL8367B_REG_MIB_COUNTER0 + 3;
	else
		regAddr = RTL8367B_REG_MIB_COUNTER0 + ((mibOff + 1) % 4);

	regData = 0;
	mibCounterOut = 0;
	while(index)
	{
		rtl_smi_read(regAddr, &regData);
		RTL8367_DEBUG("Read from 0x%x is 0x%x \n", regAddr, regData);

		mibCounterOut = (mibCounterOut << 16) | (regData & 0xFFFF);
		/*RTL8367_DEBUG("mibCounterOut 0x%x \n", mibCounterOut);*/

		regAddr--;
		index--;
	}
#else
		mibCounterOut = 0;
	
		rtl_smi_read(RTL8367B_REG_MIB_COUNTER0 + 1, &regData);
		mibCounterOut = (regData & 0xFFFF);
	
		rtl_smi_read(RTL8367B_REG_MIB_COUNTER0, &regData);
		mibCounterOut = (mibCounterOut << 16) | (regData & 0xFFFF);
	
#endif

	printf("Port %02d\t", port);
	printf("IN:0x%08x\tOUT:0x%08x\n", mibCounterIn, mibCounterOut);
	
}
void rt_rtl8367_stat(u32 port)
{
	u32 index;
	printf("==============================\n");
	printf("Port Stat:\n");
	if (port <= 7)
	{
		rt_rtl8367_stat_port_save(port);
		printf("==============================\n");
		return;
	}

	for (index = 0; index <= 7; index++)
	{
		rt_rtl8367_stat_port_save(index);
	}
	printf("==============================\n");
	return;

	
}


rtk_api_ret_t enableEthForward()
{
	rtk_api_ret_t ret;
	int index = 0;
	u32 portIsolationCtrlReg = 0x08a2;
	u32 portMatrixCtrlReg = 0x2004;

#ifdef CONFIG_TP_MODEL_C2V1
	for (index = 0; index < 5; index++)
	{
		rtl_smi_write(portIsolationCtrlReg + index, 0xff);
	}
#endif

#ifdef CONFIG_TP_MODEL_C20iV1
	for (index = 0; index < 5; index++)
	{
		*(unsigned long *)(RALINK_ETH_SW_BASE+portMatrixCtrlReg + index * 256) = 0xff0003;
	}
#endif

	RTL8367_DEBUG("enable switch forward...\n");

	return RT_ERR_OK;
}

rtk_api_ret_t disableEthForward()
{
	rtk_api_ret_t ret;
	int index = 0;
	u32 portIsolationCtrlReg = 0x08a2;
	u32 portMatrixCtrlReg = 0x2004;

#ifdef CONFIG_TP_MODEL_C2V1
	for (index = 0; index < 5; index++)
	{
		rtl_smi_write(portIsolationCtrlReg + index, 0x0);
	}
#endif
	
#ifdef CONFIG_TP_MODEL_C20iV1
	for (index = 0; index < 5; index++)
	{
		*(unsigned long *)(RALINK_ETH_SW_BASE+portMatrixCtrlReg + index * 256) = 0x0;
	}
#endif

	RTL8367_DEBUG("disable switch forward...\n");

	return RT_ERR_OK;
}

int isEthForwardEnable()
{
	int index = 0;
	u32 portIsolationCtrlReg = 0x08a2;
	u32 portMatrixCtrlReg = 0x2004;
	u32 data;

#ifdef CONFIG_TP_MODEL_C2V1
	for (index = 0; index < 5; index++)
	{
		rtl_smi_read(portIsolationCtrlReg + index, &data);
		RTL8367_DEBUG("port %d is 0x%x\n", index, data);
		if (data ^ 0xff)
		{
			return 0;
		}
	}
#endif
	
#ifdef CONFIG_TP_MODEL_C20iV1
	for (index = 0; index < 5; index++)
	{
		data = *(unsigned long *)(RALINK_ETH_SW_BASE+portMatrixCtrlReg + index * 256);
		RTL8367_DEBUG("port %d is 0x%x\n", index, data);
		if (data != 0xff0003)
		{
			return 0;
		}
	}
#endif

	return 1;
}


rtk_api_ret_t ipMcastRuleSet(struct rtl8367IpMcastRule ipMcastRule, ipMcastRuleType ruleType)
{
	rtk_l2_ucastAddr_t l2_entry;
	rtk_portmask_t pmsk;
	rtk_api_ret_t ret;
	
	l2_entry.ivl = 1;
	l2_entry.cvid = LAN_VLAN_ID;
	l2_entry.fid = 0;
	l2_entry.efid = 0;

	if (ruleType > PORT_END)
	{
		return RT_ERR_FAILED;
	}
	
	if ((ret = rtk_l2_addr_get(&(ipMcastRule.mac), &l2_entry)) != RT_ERR_OK)
	{
		RTL8367_ERROR("get L2 addr error: 0x%08x...\n", ret);
		return ret;
	}

	if ((ret = rtk_l2_ipMcastAddr_get(0x0, ipMcastRule.ip_addr, &pmsk)) != RT_ERR_OK)
	{
		if (ret == RT_ERR_L2_ENTRY_NOTFOUND)
		{
			pmsk.bits[0] = 0;
		}
		else
		{
			RTL8367_ERROR("get ipMcastAddr error: 0x%08x...\n", ret);
			return ret;
		}
	}
	
	if (ruleType == PORT_ADD)
	{
		pmsk.bits[0] |= (1 << 7) | (1 << l2_entry.port);
	}
	else if (ruleType == PORT_DEL)
	{
		pmsk.bits[0] &= ~(1 << l2_entry.port);
	}
	
	if ((ret = rtk_l2_ipMcastAddr_del(0x0, ipMcastRule.ip_addr)) != RT_ERR_OK)
	{
		if (ret != RT_ERR_L2_ENTRY_NOTFOUND)
		{
		RTL8367_ERROR("del ipMcastAddr error: 0x%08x...\n", ret);
		return ret;
	}
	}
	
	if ((ret = rtk_l2_ipMcastAddr_add(0x0, ipMcastRule.ip_addr, pmsk)) != RT_ERR_OK)
	{
		RTL8367_ERROR("add ipMcastAddr error: 0x%08x...\n", ret);
		return ret;
	}

	if ((ret =rtk_l2_ipMcastAddrLookup_set(LOOKUP_DIP)) != RT_ERR_OK)
	{
		RTL8367_ERROR("set lookup table error: 0x%08x...\n", ret);
		return ret;
	}
	
	return RT_ERR_OK;
}

rtk_api_ret_t MT7620IpMcastRuleSet(struct rtl8367IpMcastRule ipMcastRule, ipMcastRuleType ruleType)
{
	unsigned char pmsk;
	unsigned char portMsk;
	rtk_api_ret_t ret;
	
	if (ruleType > PORT_END)
	{
		return RT_ERR_FAILED;
	}
	
	if ((ret = mtk_l2_addr_get(ipMcastRule.mac.octet, &portMsk)) != RT_ERR_OK)
	{
		RTL8367_ERROR("get L2 addr error: 0x%08x...\n", ret);
		return ret;
	}

	if ((ret = mtk_l2_ipMcastAddr_get(ipMcastRule.ip_addr, &pmsk)) != RT_ERR_OK)
	{
		if (ret == RT_ERR_L2_ENTRY_NOTFOUND)
		{
			pmsk = 0;
		}
		else
		{
			RTL8367_ERROR("get ipMcastAddr error: 0x%08x...\n", ret);
			return ret;
		}
	}
	
	if (ruleType == PORT_ADD)
	{
		pmsk |= (1 << 6) | portMsk;
	}
	else if (ruleType == PORT_DEL)
	{
		pmsk &= ~portMsk;
	}
	RTL8367_DEBUG("pmsk is 0x%x\n", pmsk);

	if ((ret = mtk_l2_ipMcastAddr_del(ipMcastRule.ip_addr)) != RT_ERR_OK)
	{
		if (ret != RT_ERR_L2_ENTRY_NOTFOUND)
		{
		RTL8367_ERROR("del ipMcastAddr error: 0x%08x...\n", ret);
		return ret;
	}
	}

	if ((ret = mtk_l2_ipMcastAddr_add(ipMcastRule.ip_addr, pmsk)) != RT_ERR_OK)
	{
		RTL8367_ERROR("add ipMcastAddr error: 0x%08x...\n", ret);
		return ret;
	}
	
	RTL8367_DEBUG("igmp snooping set inner: 0x%x\n", *(unsigned long *)(RALINK_ETH_SW_BASE+0x0018));
	return RT_ERR_OK;
}

void rt_rtl8367_init()
{
	RTL8367_DEBUG("switch init Begin\n");
	u32 data;
	u32 counter = 0;
	rtk_api_ret_t ret;
	rtk_portmask_t portMask;

	extern rtk_api_ret_t (*ipMcastRuleSet_pointer)(struct rtl8367IpMcastRule ipMcastRule, ipMcastRuleType ruleType);

#ifdef CONFIG_TP_MODEL_C20iV1
	if ((ret = setVlanInner()) != RT_ERR_OK)
	{
		RTL8367_ERROR("set vlan inner error: 0x%08x...\n", ret);
		return;
	}
	//igmp snooping set
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x0018) = 0xe7d41;//0x7f1e7d7f; /* enable IGMP and MLD snooping.  */
	RTL8367_DEBUG("igmp snooping set inner: 0x%x\n", *(unsigned long *)(RALINK_ETH_SW_BASE+0x0018));

	*(unsigned long *)(RALINK_ETH_SW_BASE+0x2008) = 0xb7ff;
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x2108) = 0xb7ff;
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x2208) = 0xb7ff;
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x2308) = 0xb7ff;
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x2408) = 0xb7ff;
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x2508) = 0xb7ff;
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x2608) = 0xb7ff;

	/*  init ipMcastRule handle function */
	ipMcastRuleSet_pointer = MT7620IpMcastRuleSet;
	
	if ((ret = disableEthForward()) != RT_ERR_OK)
	{
		RTL8367_ERROR("disable switch forward error: 0x%08x...\n", ret);
		return;
	}
	
	return;
#endif

#if 1
	while(1)
	{
		rtl_smi_read(0x2002, &data);
		if (0x1c == data)
		{
			break;
		}
		else if (0x70 == data)
		{
			RTL8367_DEBUG("MT7620 SMI Init ERROR\n");
			return;
		}
		
		if (counter == 0)
		{
			printf("Wait for RTL8367RB Ready\n");
		}
		else if (counter >= 100)
		{
			/* about 10s */
			printf("\nTimeout\n");
			return;
		}
		udelay (10000 * 10);
		printf(".");
		counter++;
	};
	printf("\nRTL8367RB is ready now!\n");
#endif

	if ((ret = rtk_switch_init()) != RT_ERR_OK)
	{
		RTL8367_ERROR("init switch error: 0x%08x...\n", ret);
		return;
	}

	externalInterfaceDelay();
	rt_rtl8367_enableRgmii();

	if ((ret = rt_rtl8367_initVlan()) != RT_ERR_OK)
		{
		RTL8367_ERROR("init vlan error: 0x%08x...\n", ret);
		return;
		}
	
	if ((ret = setVlanRtl8367()) != RT_ERR_OK)
	{
		RTL8367_ERROR("set vlan 8367 error: 0x%08x...\n", ret);
		return;
	}

	if ((ret = setVlanInner()) != RT_ERR_OK)
	{
		RTL8367_ERROR("set vlan inner error: 0x%08x...\n", ret);
		return;
	}

	portMask.bits[0] = 0x41;/*  port 0 and 6 0100,0001 */
	if ((ret = rtk_igmp_static_router_port_set(portMask)) != RT_ERR_OK)
	{
		RTL8367_ERROR("set igmp router port error: 0x%08x...\n", ret);
		return;
	}

	/*  init ipMcastRule handle function */
	ipMcastRuleSet_pointer = ipMcastRuleSet;
	
	if ((ret = disableEthForward()) != RT_ERR_OK)
	{
		RTL8367_ERROR("disable switch forward error: 0x%08x...\n", ret);
		return;
	}
	
}

/**************************************************************************************************/
/*                                           GLOBAL_FUNCTIONS                                     */
/**************************************************************************************************/

