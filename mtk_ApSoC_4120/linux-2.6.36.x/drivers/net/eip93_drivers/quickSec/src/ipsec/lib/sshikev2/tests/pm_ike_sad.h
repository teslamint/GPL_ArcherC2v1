/*
 *
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
 *  Copyright:
 *          Copyright (c) 2004, 2005 SFNT Finland Oy.
 */
/*
 *        Program: sshikev2
 *
 *        Creation          : 09:43 Jan 24 2005 kivinen
 *        Last Modification : 09:44 Jan 24 2005 kivinen
 *        Last check in     : $Date: 2012/09/28 $
 *        Revision number   : $Revision: #1 $
 *        State             : $State: Exp $
 *        Version           : 1.2
 *        
 *
 *        Description       : SAD handle structure
 *
 */


#ifndef PM_IKE_SAD_H
#define PM_IKE_SAD_H

#include "sshadt.h"
#include "sshadt_list.h"
#include "sshikev2-payloads.h"

struct SshSADHandleRec {
  SshADTContainer ts_free_list;
  SshADTContainer sa_free_list;
  SshADTContainer conf_free_list;

  SshADTContainer ike_sa_by_spi;
  SshADTContainer ipsec_sa_by_spi;

  SshUInt32 ipsec_spi_counter;

  SshIkev2PayloadSA default_ike_sa;
  SshIkev2PayloadSA default_ipsec_sa;
  SshIkev2PayloadSA default_ike_nosa;
  SshIkev2PayloadSA default_ipsec_nosa;
};

typedef struct SshSADHandleRec  SshSADHandleStruct;

#endif /* PM_IKE_SAD_H */
