/**

    SIP (Session Initiation Protocol) application gateway definitions 
    and prototypes.

    <keywords Session Initiation Protocol (SIP), 
    SIP (Session Initiation Protocol), ALG/SIP>

    File: appgw_sip.h

    @copyright
    Copyright (c) 2003 - 2007 SFNT Finland Oy, all rights reserved. 

*/

#ifdef SSHDIST_IPSEC_FIREWALL

#include "sshfsm.h"
#include "appgw_api.h"
#include "sshadt_bag.h"

typedef struct SshAppgwSipRec *SshAppgwSip;
typedef struct SshAppgwSipRec  SshAppgwSipStruct;

typedef struct SshAppgwSipConfigRec *SshAppgwSipConfig;
typedef struct SshAppgwSipConfigRec  SshAppgwSipConfigStruct;

struct SshAppgwSipRec
{
  SshPm pm;
  SshADTContainer sessions;

  unsigned int registered:3;
  unsigned int instances:3;
  unsigned int shutdown:1;
  unsigned int shutdown_pending:1;

  SshFSMStruct fsm;

  /** Port map is an array of size [baseport, baseport+nports] bits.
      Bit one indicates that the port at this offset is being used, and 0
      that the port is free. Currently the system is considering a portmap at
      offset stored at soffset (however the whole bitmap is searched). */
  unsigned char *portmap;
  size_t portmap_size;

  /* Temporary; until ssh_appgw_done works properly on UDP flows: */

  /** This array (size '8*portmap_size', store handles that can be used to
      close dynamic ports. */
  SshUInt32 *portmap_handles;

  SshUInt16 baseport;
  SshUInt16 current_offset;

  SshAppgwSipConfig config;
};


typedef struct SshSdpHdrRec *SshSdpHdr;
typedef struct SshSdpHdrRec  SshSdpHdrStruct;
struct SshSdpHdrRec
{
  char **v; size_t num_v;
  char **c; size_t num_c;
  char **o; size_t num_o;
  char **m; size_t num_m;
  char **unhandled; size_t num_unhandled;
};

typedef struct SshSipHdrRec *SshSipHdr;
typedef struct SshSipHdrRec  SshSipHdrStruct;
struct SshSipHdrRec
{
  /* First we cache some information how and where this particular SIP
     packet was received. */

  /** The IP protocol the packet arrived from, we send using the same. */
  SshInetIPProtocolID proto;

  unsigned int is_request:1;

  unsigned int from_internal:1;
  unsigned int from_initiator:1;

  unsigned int payload_sip:1;
  unsigned int payload_sdp:1;

  /** The appgw instance this particular packet arrived from. */
  SshAppgwContext instance;

  /** The actual packet payload information is below. */
  union {
    struct {
      char *method;
      char *uri;
      char *version;
    } request;
    struct {
      char *version;
      int value;
      char *phrase;
    } response;
  } u;

  char **call_id; size_t num_call_id;
  char **contact; size_t num_contact;
  char **from; size_t num_from;
  char **to; size_t num_to;
  char **via; size_t num_via;

  char **content_type; size_t num_content_type;
  size_t content_length;

  char **unhandled; size_t num_unhandled;

  struct {
    unsigned int request_uri:1;

    unsigned int callid:1;
    unsigned int contact:1;
    unsigned int from:1;
    unsigned int to;
    unsigned int via:1;
  } change;

  union {
    struct {
      size_t content_len;
      unsigned char *content;
    } sip;
    struct {
      unsigned int mapped:1;
      SshSdpHdr header;
    } sdp;
  } payload;

  /** Next entry on the queue waiting for being processed. */
  SshSipHdr next;
};

struct SshAppgwSipOpenPortRec
{
  SshUInt16 port;
  SshUInt16 nports;
};
typedef struct SshAppgwSipOpenPortRec *SshAppgwSipOpenPort;
typedef struct SshAppgwSipOpenPortRec  SshAppgwSipOpenPortStruct;

struct SshAppgwSipConnectionRec
{
  unsigned int initiated_from_inside:1;
  unsigned int port_open_failed:1;
  unsigned int terminating:1; /** Set when bye received. */
  unsigned int terminated:1;  /** Set when terminating timeout reached. */

  /** Session identifying triplet from the session identifier, prior to
      any ALG compensations. */
  char *from;
  char *to;
  char *call_id;

  /** Application gateway address - the value the ALG uses to map. */
  char *appgwaddr;
  /** Local address - the value the ALG uses to map. */
  char *localaddr;

  /** Headers for the current packets being processed. */
  SshSipHdr c_siphdr;

  /** SDP port open information: number of transport ports. */
  SshUInt32 num_transport_ports;
  /** SDP port open information: transport ports. */
  SshAppgwSipOpenPort transport_ports;

  SshFSMThreadStruct thread;
  SshFSMConditionStruct packet_received;

  SshADTBagHeaderStruct bag_header;
  SshTimeoutStruct timeout;

  /** The master instance, destroyed only when the session is closed.
      Individual packets may have different instances that are used
      only during that packet, and destroyed immediately (unless it is
      the same instance as the master). */
  SshAppgwContext instance;
};

typedef struct SshAppgwSipConnectionRec *SshAppgwSipConnection;
typedef struct SshAppgwSipConnectionRec  SshAppgwSipConnectionStruct;


/** Parse SIP header from data. At the end, 'endptr' will be set to
    point to the beginning of the SIP payload data, if any or NULL.  
    Data gets corrupted during process. */
SshSipHdr alg_sip_parse_response(char *data, char **endptr);
SshSipHdr alg_sip_parse_request(char *data, char **endptr);

/* Write parsed sip header into buffer. */
char *    alg_sip_write_sip_header(SshSipHdr siphdr);

void      alg_sip_free_header(SshSipHdr siphdr);

/** Parse SDP (Session Description Protocol) header from data.  In the
    end, 'endptr' will be set to point to the beginning of the SDP 
    payload data, if any or NULL.  Data gets corrupted during process. */
SshSdpHdr alg_sip_parse_sdp(char *data, char **endptr);
Boolean
alg_sip_parse_sdp_m(const char *mline,
		    char **media,
		    SshUInt16 *port, SshUInt16 *nports,
		    char **proto,
		    char **rest);

char *
alg_sip_write_sdp_m(const char *media,
		    SshUInt16 port, SshUInt16 nports,
		    const char *proto,
		    const char *rest);


Boolean
alg_sip_parse_sdp_c(const char *cline,
		    char **nettype, char **addrtype, char **address);

char *
alg_sip_write_sdp_c(const char *nettype,
		    const char *addrtype,
		    const char *address);


Boolean
alg_sip_parse_sdp_o(const char *oline,
		    char **user,
		    char **session, char **version,
		    char **nettype, char **addrtype, char **address);


char *alg_sip_write_sdp_o(const char *user, const char *session,
			  const char *version, const char *nettype,
			  const char *addrtype, const char *address);


/** Write the parsed SIP header into the buffer. */
char *    alg_sip_write_sdp_header(SshSdpHdr sdphdr);

void      alg_sip_free_sdp_header(SshSdpHdr sdphdr);

typedef void (*SshAppgwSipPortCB)(SshUInt16 baseport,
				  SshUInt16 nports,
				  void *callback_context);


/* Create an object holding a configuration of an SIP  appgw.

 @return
    The function returns NULL if it runs out of memory. */

SshAppgwSipConfig
ssh_appgw_sip_config_create(void);


/* This functions add the private internal network which
  can intiate SIP calls   on which SIP APPGw processing
  would happen.more then one such networks can be added.
   
 @param configurations
 SshAppgwSipConfig context returned by the ssh_appgw_sip_config_create.

 @param intnet
 ip address range of private internal network.
 
 @return
 None
  								*/
void
ssh_appgw_sip_add_internal_network(SshAppgwSipConfig configuration,
				   const SshIpAddr intnet);

/** This function returns the configured internal networks indexed upon 
    the num_internal_network parameter. If Application has to find out 
    that if some ip address matches the range configured   it would have
    parse through all the configured internal network.  Sip Configuration
    object have the count of total number of internal network configured.

@param  configuration
Appgw configuration context to be manipulated

@param num_internal_networks


@return
ip address range

  								*/
SshIpAddr
ssh_appgw_sip_get_internal_networks(SshAppgwSipConfig configuration,
				    size_t *num_internal_networks);

/**
 The NAT is configured with a static mapping or "conduit"
 for each of these internal SIP servers from public IP addresses
 (typically on the well-know SIP port--5060) to their internal IP
 addresses. The Enterprise can then advertise these public addresses
 in DNS A or SRV records.This function set up the conduit mapping.
 There can be more then one conduit mapping.

@param configuration
SIP appgw configuration context to be manipulated

@param external
External IP address 

@param external_port
External Port

@param internal 
Internal SIP server IP address

@param internal_port
Internal SIP port on which SIP server is listening for the request

@return 
Void
  								*/
void
ssh_appgw_sip_add_conduit(SshAppgwSipConfig configuration,
			  const SshIpAddr external,
			  SshUInt16 external_port,
			  const SshIpAddr internal,
			  SshUInt16 internal_port);

/*
 * This function provides the current status conduit indexed on nth.

@param 
SIP appgw configuration context to be manipulated

@param nth

@param  external
External IP Address mapped

@param external_port
External port

@param internal
Ip Address of internal ip address

@param internal_port
Internal port

@return
True if the mapping exists & False if the mapping does not exist

*/
Boolean
ssh_appgw_sip_get_conduit(SshAppgwSipConfig configuration,
			  SshUInt32 nth,
			  SshIpAddr external, SshUInt16 *external_port,
			  SshIpAddr internal, SshUInt16 *internal_port);

/*This function is used at time for packet processing to decide which 
  mapping should be applied. 

 @param configuration
 SIP appgw configuration context to be manipulated

 @param address
 Ip Address

 @param to_external
 Direction of packet is going.

 @return
 Null if no mapping exists matching the address
 mapped Ip Address if the the mapping exists 
  								*/
SshIpAddr
ssh_appgw_sip_conduit_apply(SshAppgwSipConfig configuration,
			    SshIpAddr address,
			    Boolean to_external);
/*Destroys the sip configuration object   Application which
  has created the configuration   object & should also destroy
  this before the shutdown. @param configuration   SIP appgw
  configuration context to be manipulated

 @return void
  								*/
void
ssh_appgw_sip_destroy_config(SshAppgwSipConfig configuration);

/*This function marshals the configuration config into a
  platform-independent representation. The buffer returns a
  pointer to a buffer containing the marshaled representation
  and places the length of this  buffer in *res len.

 The SIP application gateway expects a data blob produced
 by ssh_appgw_sip_marshal_config to  be provided to it via
 ssh_ pm_service_set_appgw_config for the services which use 
 the application  gateway.

 The function returns NULL if there is insufficient memory
 available to complete successfully.

 The caller of the function is expected to ssh free the
 returned buffer after having finished using it.

 @param configuration
 SIP appgw configuration context to be manipulated

 @param marshalled_len
 A pointer to the length of the returned buffer.
 
 @return  
 The function returns NULL if there is insufficient
 memory available to complete successfully.

*/


unsigned char *ssh_appgw_sip_marshal_config(SshAppgwSipConfig configuration,
                                            size_t *marshalled_len);

/*
  This function unmarshals a configuration back into a 
  SshAppgwSipConfig object. 

 @param data
 A buffer containing a marshaled configuration.

 @len
 The length of the marshaled representation in bytes.

 @return
 The function returns NULL if there is insufficient memory available.
 The caller is expected to free the configuration.
  								*/
SshAppgwSipConfig
ssh_appgw_sip_unmarshal_config(const unsigned char *data,
                               size_t len);



Boolean alg_sip_parse_sip_via(const char *vialine,
			      char **proto,
			      char **sent, SshUInt16 *port,
			      char **params);
char *alg_sip_write_sip_via(char *proto,
			    char *sent, SshUInt16 port,
			    char *params);

Boolean alg_sip_parse_sip_address(const char *addrline,
				  char **displayname,
				  char **user, char **host,
				  char **params);

char *alg_sip_write_sip_address(char *displayname,
				char *user, char *host,
				char *params, Boolean uri_p);

SshOperationHandle
alg_sip_open_transport(SshAppgwSip alg,
		       SshAppgwContext instance,
		       Boolean initiator_inside,
		       SshUInt16 dstport, SshUInt16 nports,
		       SshAppgwSipPortCB callback,
		       void *callback_context);

void
alg_sip_close_transport(SshAppgwSip alg,
			SshAppgwContext instance,
			SshUInt16 baseport, SshUInt16 nports);

#endif /* SSHDIST_IPSEC_FIREWALL */
/* Config */
