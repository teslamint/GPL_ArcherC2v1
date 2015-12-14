#
#  Quicksec toolkit for VxWorks README.txt
#
#  Copyright (c) 1999-2006 SFNT Finland
#  All rights reserved

#
#  These instructions apply to the version they are distributed with.
#


Setup Instructions
------------------

For step-by-step setup and compilation instructions, please refer to 
the Quick Start Guide. 


*******************************************************************************
* Note: The text below is written for SSH Ipsec Express toolkit,              *
* but is mostly valid for Quicksec also.                                      *
*******************************************************************************


SSH IPSEC toolkit for WindRiver VxWorks
---------------------------------------

Introduction

The VxWorks IPSEC toolkit port is based on the NetBSD SSH IPSEC toolkit
source code, because of the similarities between these two systems. The
NetBSD code was taken as a basis for the port and then the necessary
changes were designed in order to get the SSH IPSEC system operate in
VxWorks with the full set of features available for NetBSD. Most of the
changes for VxWorks are in the packet interceptor and packet manipulation
part of the code and in the character device. Additionally there are small
changes in the SSH libraries (e.g. fcntl was replaced with ioctl for
VxWorks). Because of the highly portable nature of the SSH IPSEC source
code these changes could be isolated behind well defined application
programming interfaces. Practically all of the supporting library code,
e.g. crypto-libraries, could be compiled for VxWorks without intervention.

Because VxWorks does not make a distinction between the kernel-mode and
user-space, i.e. everything is executed in kernel-mode, the SSH IPSEC code
should never use ssh_kmalloc etc. functions. Instead all of these calls
are replaced with ssh_xmalloc. This is done by defining the needed macros
in the sshincludes_vxworks.h header file.


Engine (interceptor)

Generally the SSH IPSEC engine needed very little attention during the
VxWorks port. In VxWorks the SSH IPSEC engine code is executed at
tNetTask level, the stack size of which is increased by setting
external symbol netTaskStackSize before initializing the rest of the
system, i.e. in the beginning of the root task (usrRoot). See the
Porting Manual for details.


Policy Manager

In VxWorks the SSH IPSEC policymanager code is executed in its own
task tIpsec. Options for this task such as stack size, are set in
quicksecpm_vxworks.c.


The Packet Interceptor for VxWorks

The VxWorks-specific part of the packet interceptor is located in
icept_attach_vxworks.c. Parts common to BSD platforms are implemented
in icept_kernel_interceptor_bsd.c

To capture packets received from a network interface, the packet
interceptor binds the function ssh_icept_from_network() to the
interface as a SNARF receive handler using muxBind(). The interceptor
captures IPv4, ARP and IPv6 packets only; other packets are not
consumed by the interceptor, i.e. they will be passed to other MUX
receive handlers.

To capture packets transmitted by the TCP/IP stack to a network
interface, the interceptor replaces the interface output routine
(i.e. the if_output pointer of struct ifnet) of each network interface
with the function ssh_icept_from_protocol(). This function will give
IPv4, ARP and IPv6 packets to the QuickSec engine whereas other
packets are passed unchanged to the original interface output routine.

Packets sent by the QuickSec engine to a network interface are sent
using the original interface output routine of the interface in
ssh_interceptor_mbuf_send_to_network().

Packets sent by the engine to the TCP/IP stack are passed to either
ip_input(), in_arpinput() or ip6_input() (with earlier VxWorks network
stacks, ipintr(), arpintr() or do_protocol_with_type() is used). This
is implemented in ssh_interceptor_mbuf_send_to_protocol().

An intercepted packet is always passed to the QuickSec engine in
tNetTask context; if a packet is intercepted within another context it
will be passed to tNetTask using a netJobAdd() call and then to the
QuickSec engine within tNetTask context.


Packet And The Memory Buffer Manipulation for VxWorks

The SSH packet interceptor packet manipulation functions are done based on
the icept_kernel_interceptor_bsd.c C-file, utilizing the NetBSD
portability layer provided by WindRiver VxWorks in
$(WIND_BASE)/target/h/net/mbuf.h. This is not a complete implementation
though, so the NetBSD memory buffer (mbuf) portability functions are tuned
with additional macros for VxWorks (and a bugfix for the WindRiver code)
in icept_mbuf_vxworks.h header file and in the beginning of
icept_kernel_interceptor_bsd.c C-file. After implementing these layers,
utilizing the BSD TCP/IP protocol layer memory block and memory cluster
pools (_pNetDpool), the only remaining difference was the fact that the
clusted size may vary in VxWorks, whereas it is fixed size in NetBSD (2048
bytes). Additionally the memory block cannot contain any payload data in
VxWorks, whereas in NetBSD, it can store up to 128 bytes of data. By
adding the following macros to be used in the code these differences could
be optimized for VxWorks in a clean way, i.e. not messing up the NetBSD
implementation.

#define SSH_MCLGET(m, wait, size) \
  mClGet(_pNetDpool,(m),(size),(wait),FALSE)

#define SSH_MCLBYTES(m) (m)->m_extSize

Note that the 'bestFit' parameter of the VxWorks mClGet function must be
FALSE, when allocating clusters for large packets. For large packets the
memory buffer chains contain a linked list of memory buffers (mbuf) and
thus mClGet must be allowed to return smaller than requested clusters.


Constructing the interface list in VxWorks

Information about network interfaces in the system is obtained in the
same way as in other BSD-based systems, i.e. iterating through the
global interface list. This is implemented in in
icept_kernel_interceptor_bsd.c. When the interface list is scanned,
the interceptor will attach itself to any new interfaces
(e.g. dial-up). A separate task tQcNotif, implemented in
icept_kernel_stubs_vxworks.c monitors routing and interface changes
through a routing socket and initiates scanning of the interface list
as necessary.

The timeout implementation for VxWorks

The timeout implementation is done utilizing the POSIX timers in VxWorks.
The number of timers for each task is limited by default to 32 in VxWorks
file $(WIND_BASE)/target/h/time.h. It is highly advisable to increase this
number to at least 4096.

   #define _POSIX_TIMER_MAX      4096	/* max. per task */
   #define _POSIX_DELAYTIMER_MAX 4096	/* max. expired timers */

It should be noted that the VxWorks POSIX timer callback function task
execution level is 'system', and thus might cause synchronization problems
with the tNetTask running all other SSH IPSEC packet interceptor code.
That is why the VxWorks POSIX timer callback is wrapped to tNetTask with
the VxWorks netJobAdd() function. The implementation of SSH timeout can be
found in icept_kernel_stubs_vxworks.c C-file.


The character device

Communication between policy manager and ipsec engine has been implemented
as a character-special device driver, by default registered as device
"/ipsec". Current implementation support only one such device per system,
however that can be changed easily if required.

A device uses one entry in driver table, one entry in device table, one
binary semaphore and allows one open file descriptor. The device
implements necessary functions, according to VxWorks manuals (specifically
"VxWorks Programmer's Guide", chapters 3.9.1 - 3.9.3 "I/O System" -
"Internal Structure" - "Drivers"/"Devices"/"File Descriptors")  and ssh
"engine- porting" guide (which see).

Only one file descriptor can be open for a device, moreover device assumes
that only one task is using it at any given time.


read call

Upon a read call, messages are read from the queue, as many as would fit
in the user-supplied buffer. Function returns number of bytes actually
written to the user buffer, and if no were, sets errno to EAGAIN and
returns -1.


write call

Upon a write call, the user-supplied buffer is parsed and messages are fed
to the engine through 'netJobAdd()' prototype, because write call is
executed at the user task level. The number of messages which get
successfully fed depends on two constraints - if 'netJobAdd()' fails, this
and following messages can not be transferred and there is also a
heuristic limit (20 by default), which is used to avoid filling up netLib
queue (default size 63, if queue is full packets coming from the network
will be dropped). The function returns the number of bytes actually
transferred, however, by the time function returns engine has hardly
processed these messages yet. If no data was transferred, function set
errno to EAGAIN and returns -1.


select() support

The device supports select() by implementing FIOSELECT and FIOUNSELECT
ioctl function codes. However device cannot reliably detect if 'write'
operation would succeed or not, because there is no way to check if there
is any space left in netLib queue, and because even if there was, network
driver(s) could accidentally fill it at any give time. Therefore the
provision made to ensure that device user (policymanager) cannot go into
an infinite loop attempting to write in a full queue is higher priority of
tNetTask than that of tSshIpm.

More information is available in the source file icept_chardev_vxworks.c.


Changes to the libraries

Due to the highly portable nature of SSH IPSEC library code, the changes
needed for VxWorks could be limited to the following functions. These are
described in subsequent sections.

* ioctl
* open
* case
* host
* serv
* kill


ioctl

Since VxWorks doesn't have fcntl function and event loop module requires
all registered file descriptors to be non-blocking, function
XXX_register_fd was modified to call ioctl(fd, FIONBIO, &((int) 1))
instead of fcntl. The drawback of this change (implied by the limitation
of VxWorks mentioned above) is that it is not possible to restore file
descriptor to its original state when it is unregistered (there is no way
to query if file descriptor was non-blocking before it was explicitly set
so in XXX_register_fd call). Thus all file descriptors become non-blocking
in XXX_register_fd call and remain such after XXX_unregister_fd call. If
any 'user' of event loop needs to restore file a file descriptor in it's
original state after deregistering it, it has to do so itself and keep
track of original state outside of event loop module.


open

VxWorks requires exactly 3 arguments in open() system call (whereas other
OS-es allow both 2 arguments and 3 arguments). All relevant occurences
were modified by adding 3rd argument of 0. Apparently open() call was not
used in any of those occurences to create a file.


case

VxWorks does not provide case-insensitive comparison functions (namely
strcasecmp and strncasecmp), these are compiled from source provided with
the toolkit in src/lib/sshutil/sshcore/ directory.


host

VxWorks has different prototypes for hostname to [ip] address translation
(or vice versa) than unices, thus corresponding changes were made.

NOTE 1: VxWorks' hostLib is case sensitive.

NOTE 2: if dynamic address resolution is enabled in VxWorks and a
particular request cannot be satisfied by cache or static entries in
hostLib, the query will be done. In this case [current] implementation
will *block* for default timeout value.

NOTE 3: if dynamic address resolution is disable in VxWorks, dns query
cannot be done at all, which means that available symbolic names are
limited to manual entries in hostLib.


serv

VxWorks does not provide service to port translation (or vice versa),
therefore directory src/lib/sshutil/sshnet/unix/ contains the following:

1) prebuilt file 'sshgetservbyname_servicetable.c' with
   service name <-> port number translation table

2) a shell script 'servicer' which can be used to generate that file
   from unix(? or posix?) style /etc/services. One notable restriction
   of that script is that it doesn't handle duplicate service
   name/protocol/port tripples gracefully.


kill

VxWorks does not have processes. Furthermore signals are thread-specific
as opposed to process-specific notion in unices. Currently getpid() is
substitued with taskIdSelf(), however if the policy manager code is to be
ran in more than one task, this will not work correctly.


Encountered WindRiver VxWorks Operating System bugs
---------------------------------------------------

1. Title: alignment exception for END driver.
---------------------------------------------

SPR: 22788

Patch:

Host: All

Architecture: All

bsp: All

Product: VxWorks Version: 5.4


Problem Description
-------------------

There is a restriction in the network stack which requires that data
buffers be offset by two bytes from a longword alignment. This can
cause problems such as the system getting an alignment exception
generated in ipintr. Also, if a driver receives packets OK but the
target sends ICMP redirects, it is likely to be caused by not handling
this alignment restriction. This can be caused by improper
configuration of the offset parameter when a driver is installed, but
it is also sometimes caused by not handling the alignment restriction
in a driver written from scratch or ported from some other platform.

SPR #22788 "Remove alignment restrictions from the TCP/IP stack when
receiving packets" has been filed against this issue. Here is what is
happening. When an Ethernet packet comes in, it begins with a 14-byte
Ethernet header including the destination MAC address (6 bytes), the
source MAC address (6 bytes), and either the IEEE 802.3 packet length
(2 bytes) or an Ethernet type field (2 bytes, 0x0800 is for
IP). Following the Ethernet header is the IP header, which includes
the IP addresses of the source and destination hosts. These addresses
are 4-byte entities and are aligned the same as the beginning of the
IP header. If the driver aligns the incoming packet on 4-byte
boundaries, then the IP source and destination addresses will *not* be
4-byte aligned. When packets with this alignment are passed up to the
network stack, there can be problems related to this alignment. For
example, on ARM, the processor will fetch four bytes, but the data
will not be from the expected locations, so the addresses will not be
correct. Needless to say, this can cause problems which are difficult
to find. For a more detailed explanation, see the text of the SPR.


Problem Solution
----------------

Until this SPR is fixed, there are two possible workarounds, both of
which must be implemented in the driver:

The first and more desirable workaround is for you to offset the
buffer for incoming packets by 2. This involves incrementing the
buffer pointer by two before putting the incoming data there, and
decrementing the buffer pointer by two before freeing the buffer. For
normal Ethernet packets, this will cause the IP and TCP headers to be
word aligned for normal incoming packets. Note that the IP options
field does not affect this, since IP options must always be a multiple
of four bytes.

If that doesn't work for some reason, then the alternative is to
allocate a smaller, second buffer and copy the TCP and IP headers into
it. You would then need to modify the cluster chain before passing the
packet up into the stack. Of course, this involves overhead that would
best be avoided, but if hardware restrictions, or some other problem
make the first solution untenable, then this is a possibility. An
example of this is provided at the end of this summary.

target/src/drv/end/ln7990End.c shows how the offset parameter is used
to workaround the problem. Below is an example of how the "offset"
parameter is used in the iOlicom driver. You will have to change the
load string in configNet.h and handle the offset parameter in the
Parse function of the driver: For the iOlicom driver, the
initialization string has the following fields:

        nisa_base
        nisa_pcmcia
        nisa_pcmem
        intVectA
        intLevelA
        intVectB
        intLevelB
        txBdNum
        rxBdNum
        offset
        pShMem
        shMemSize

As for all END/NPT drivers, the fields are kept in an ascii string
with colons separating the individual fields, as follows:

    ":::::
    ::::::"

Each field contains the value of the parameter, with NULL being the
default. Check iOlicomEnd.h for a better description of each of the
fields.

The offset field contains the Memory offset for alignment as discussed
in this summary. The normal value for offset for a machine which
requires 4-byte alignment for longword accesses would be 2. For
CISC machines and machines without alignment restrictions, the
offset should be 0.

This is the fourteenth parameter passed to the driver in the init
string. This parameter defines the offset which is used to solve
alignment problem.

In iOlicomIInitMem(), you increment the buffer pointer by offset
bytes:

> /* Setup the receive ring */
>
> for (ix = 0; ix < pDrvCtrl->rxBdNum; ix++)
> {
> pBuf = (char *) NET_BUF_ALLOC();
...
> pBuf += pDrvCtrl->offset;

In iOlicomRecv(), the driver's task level receive function, the buffer
pointer must be decremented. Failure to do this will cause the buffer
free function to fail, so the cluster will never be freed back to the
buffer pool, and you will have a very fast memory leak.

> /* Get the data pointer and len from the current RX_BD */
>
> len = pRxBd->dataLength;
> pData = pRxBd->dataPointer;
>
> /*NOTE
>  * In configNet.h, the offset is 2. The cluster pool ID is the
>    cluster buffer address - 4 bytes.  Have to reset the pointer to
>    the proper place so that the cluster will be returned to
>    the pool once the stack frees it. */
>
> pData -= pDrvCtrl->offset;
>
> /* Associate the data pointer with the CL_BLK */
>
> NET_CL_BLK_JOIN (pClBlk, pData, OLI_BUFSIZ);
>
> /* Associate the CL_BLK with the MBLK */
>
> NET_MBLK_CL_JOIN (pMblk, pClBlk);
>
> pMblk->mBlkHdr.mData += pDrvCtrl->offset;
> pMblk->mBlkHdr.mFlags |= M_PKTHDR; /* set the packet header */
> pMblk->mBlkHdr.mLen = len; /* set the data len */
> pMblk->mBlkPktHdr.len = len; /* set the total len */
>
> /* Deal with memory alignment for the cluster that will replace the
> one being lent to the stack. */
>
> pBuf += pDrvCtrl->offset;
>
> /* Install the new data buffer */
>
> pRxBd->dataPointer = pBuf;
>
> /* send up to protocol */

END drivers are not required to support the polled mode functions.
However, if the driver does support polled mode, the pollReceive
function must also implement the offset adjustment.


Frequently Asked Questions
--------------------------

1. GENERAL

Q. Where is the VxWorks real-time OS used/needed?

A. For an extensive answer, see the WindRiver homepage
   (http://www.windriver.com/products/html/vxwks54.html).

Here is a short summary:

Data networking: Ethernet switches, routers, remote access servers,
                 ATM and FR switches
Industrial:      test and measurement equipment, robotics, CNC equipment,
                 process control systems
Medical:         MRI scanners, PET scanners, radiation therapy equipment,
                 bedside monitors
Digital imaging: printers, digital copiers, fax machines, multi function
                 peripherals, digital cameras
Transportation:  automotive engine control systems, traffic signal
                 control, high-speed train control, anti-skid testing
                 systems.
Telecommunications: PBXS and ACDS, CD switching systems, cellular systems,
                 XDSL and cable modems
Aerospace:       avionics, flight simulation, airline cabin management
                 systems, satellite tracking systems
Computer peripherals: X terminals, I/O control, RAID data storage systems,
                 network computers
Multimedia:      professional video editing systems, video conferencing
Consumer electronics: PDAS, set-top boxes/TV, screen phones, audio
                 equipment, car navigation systems, in-flight
                 entertainment systems


Q. What is the VxWorks equivalent of the ssh_interceptor_open() ?

A. Implements the VxWorks "fooAttach()" network protocol activation
   function of the MUX interface.


Q. How is the VxWorks BSD TCP/IP memory pool organized?

A. The NET_POOL_ID is a pointer to a netPool structure (netBufLib.h).
Have a look at netPoolInit function and its relatives (reference manual pp
2 - 515).

NETWORK STACK MEMORY POOLS

The network stack is configured with 2 pools of memory. The first pool,
the system pool: netStackSysPoolShow, is reserved for system use to store
data structures such as sockets, and routes. The second pool, the data
pool: netStackDataPoolShow, is used to copy data from task level buffers
to network stack buffers.

BSD44 network drivers will also use the network stack data pool to copy
received packets (1520 bytes in size) if the drivers have lent the network
stack the maximum number allowed. If muxShow does not show any drivers,
BSD44 drivers are configured.  BSD44 drivers are configured if T101 build
method is used, and INCLUDE_END is undefined in config.h OR in T2 Project
facility:  network components->network devices->End attach interface and
End interface support components are excluded.

VXWORKS RUNTIME IMAGE MACROS

The default allocation under Tornado 2.0 for runtime images is given by
the parameters in the Project facility, or netBufLib.h if the Tornado
1.0.1 build method is used.

The NUM_64, NUM_128... are for the data pool. The NUM_SYS_64, NUM_SYS_128
... are for the system pool.

BOOTROM IMAGE MACROS

The macros with MIN suffix (i.e. NUM_SYS_64_MIN... and NUM_64_MIN...) are
used for bootrom images which usually need to be small. The values for the
MIN macros are usually adequate to download the runtime image and do not
normally need to be changed.

For every TCP socket, the system allocates 3 clusters (1 128, 1 256, and 1
512) used for the generic protocol control block (inpcb), TCP protocol
control block, and the socket structure respectively. For every UDP
socket, the system allocates 2 clusters (1 128, 1 512) used for the inpcb
and socket structures respectively. For every route, 2 clusters (1 64, and
1 128)  are allocated.

There are 2 control data structures needed to manage the clusters:
cluster blocks, and mblocks. For each pool, there should be as many
cluster blocks as there are clusters. There should be at least as many
mblocks as there are cluster blocks.  Some extra mblocks are needed since
the system uses them, for example, to reference data in the clusters
without copying. It may not be necessary for mblocks to be 2 times the
number of cluster blocks as the default configuration assumes. As the T2
VxWorks Network Programmer's Guide advises, on Section 4.6.3, you should
adjust the values as necessary to suit your application requirements.
netStackSysPoolShow and netStackDataPoolShow can be used to display the
status of the pools.

The default configuration may have to be increased if an application opens
lots of sockets/routes (or if RIP, or web server are configured). The show
routines (netStackSysPoolShow and netStackDataPoolShow) display the number
of free clusters.  The usage statistics display the cumulative number of
times clusters of each size have been allocated. The number of times
failed to find space is also of interest.

If the pools are too small, socket applications may block or packets may
be dropped while the system waits for buffers to become available. Under
Tornado 1.0.1 with SENS 1.0 (setup.log shows SENS installed under SETUP
1.4), socket calls block and may even hang. Under Tornado 1.0.1 with SENS
1.1 (setup.log shows SENS installed under SETUP 1.5) and Tornado 2.0, if
there are no buffers, the system attempts to find buffers, and if it is
not successful the error will be reported as S_netBufLib_NO_POOL_MEMORY.


PROJECT FACILITY

network components -> basic network initialization components -> network
buffer initialization -> Params

NUM_SYS_64 = 40
NUM_SYS_128 = 40
NUM_SYS_256 = 40
NUM_SYS_512 = 20
NUM_SYS_CL_BLKS = 140
NUM_SYS_MBLKS = 2*NUM_SYS_CL_BLKS

NUM_64 = 100
NUM_128 = 100
NUM_256 = 40
NUM_512 = 40
NUM_1024 = 25
NUM_2048 = 25
NUM_CL_BLKS = NUM_64 + ...NUM_2048 = 330
NUM_NET_MBLKS = 400


Q. How can I configure two identical ISA 3c509b network interface cards
   in the system?

A. Note we are using the 3COM 3C509B ISA bus cards, not PCI. We
   have managed to have them both configured in the system
   and have them up and running with MUX, END, ifShow, MuxShow,
   TCP/IP and configure them with route with these fixes.

1. In $(WIND_BASE)/target/config/pcPentium/configNet.h
   we add these cards to the END_TBL_ENTRY endDevTbl [].
   Here we set the IRQ, I/O Base address and IRQ Vector of
   the card. Note. must be in hex (0x).

...
/* First 3c509B ISA card */
#ifdef INCLUDE_ELT_3C509_END
    {0, END_3C509_LOAD_FUNC, END_3C509_LOAD_STRING, END_3C509_BUFF_LOAN,
        NULL, FALSE},
#endif /* INCLUDE_ELT_3C509_END */

/* Second 3c509B ISA card */
#ifdef INCLUDE_ELT_3C509_END
# define DIMA_END_3C509_LOAD_FUNC elt3c509Load
# define DIMA_END_3C509_LOAD_STRING "0x250:0x2a:0xa:0:0"
    {1, DIMA_END_3C509_LOAD_FUNC, DIMA_END_3C509_LOAD_STRING,
END_3C509_BUFF_LOAN,
        NULL, FALSE},
#endif /* INCLUDE_ELT_3C509_END */
...

2. In $(WIND_BASE)/target/config/comps/src/net/usrNetEndBoot.c
   in function usrNetEndDevStart() we remove the check for
   the a second card.
...
#if 0
    if (netDevBootFlag)
        return;
#endif
...

3. In prjConfig.c in function usrNetworkDevStart()
   (or where the MUX gets initialized) we add an init call
   for the second 3C509B card.
   Here we set the IP address and subnet mask for the second if.

...
/* VxWorks calls routeAdd(subnet, if_address); second
                call to which fails for the same subnet, thus interface
                should (better) be in different subnets */
/* subnet is in *host* order */
/* Uses boot parameters to start an END driver */
    usrNetEndDevStart (pDevName, uNum, pTgtName, pAddrString, 0xffff0000);
    usrNetEndDevStart (pDevName, uNum+1, "", "10.6.6.6", 0xffff0000 );
...

Q. How do I add shell, symbol table and show routines to Makefile
   based build?

A. Add the following definitions under the included software facilities
   in file target/config/all/configAll.h

   #define INCLUDE_SHELL
   #define INCLUDE_DEBUG
   #define INCLUDE_SYM_TBL
   #define INCLUDE_STAT_SYM_TBL
   #define INCLUDE_STANDALONE_SYM_TBL
   #define INCLUDE_NET_SHOW
   #define INCLUDE_SHOW_ROUTINES
   #define INCLUDE_PING

   #define STANDALONE_NET

   (NOTE The "STANDALONE_NET" is important for the vxWorks.st build,
   otherwise the network is not initialized)

   and in the target/config/<bsp> directory type

   % make clean vxWorks.st

   then in the file target/config/<bsp>/Makefile add to

   MACH_EXTRA = symTbl.o

   And make your final VxWorks image by typing [optionally bdx]

   % make vxWorks[.bdx]


Q. Sometimes the SSH IPSEC mysteriously does not accept certificates
   coming from the CA.

A. The VxWorks timer always starts from zero and the SSH IPSEC thinks the
   date is somewhere around January 1, 1970. Thus the certificates
   are sometimes out of the validity period and rejected. Make sure your
   VxWorks system updates the system clock during startup.
