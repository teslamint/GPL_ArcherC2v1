/**
 * util_tcpencap.c
 *
 * @copyright
 *      Copyright 2007 SFNT Finland Oy -
 *      all rights reserved.
 *
 *
 */

#include "sshincludes.h"

#ifndef UTIL_TCPENCAP_H
#define UTIL_TCPENCAP_H

#ifdef SSH_IPSEC_TCPENCAP

/** IKE cookie length. This is used for identifying IKE negotiations for
    IPsec over TCP SA selection. This is defined separately here as IPsec
    over TCP works with both IKEv1 and IKEv2. */
#define SSH_IPSEC_TCPENCAP_IKE_COOKIE_LENGTH 8

#endif /* SSH_IPSEC_TCPENCAP */

#endif /* UTIL_TCPENCAP_H */
