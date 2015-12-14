/*
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
 */
/*
 *        Program: sshisakmp
 *        $Source: /home/user/socsw/cvs/cvsrepos/tclinux_phoenix/modules/eip93_drivers/quickSec/src/ipsec/lib/sshisakmp/tests/Attic/xauth_demo.c,v $
 *        $Author: bruce.chang $
 *
 *        Creation          : 16:04 Jun 14 1998 kivinen
 *        Last Modification : 06:08 Oct 26 1998 kivinen
 *        Last check in     : $Date: 2012/09/28 $
 *        Revision number   : $Revision: #1 $
 *        State             : $State: Exp $
 *        Version           : 1.81
 *        
 *
 *        Description       : Isakmp xauth test module
 *
 *
 *        $Log: xauth_demo.c,v $
 *        Revision 1.1.2.1  2011/01/31 03:29:52  treychen_hc
 *        add eip93 drivers
 * *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        $EndLog$
 */

#include "sshincludes.h"
#include "isakmp.h"
#include "sshgetput.h"

#define SSH_DEBUG_MODULE "SshIkeXauth"

#ifdef SSHDIST_ISAKMP_CFG_MODE
#include "xauth_demo.h"

/* Internal callback context structure */

typedef struct SshIkeXauthIntContextRec {
  SshIkeXauthPasswordHandler handler_callback;
  void *handler_callback_context;
} *SshIkeXauthIntContext;

void ike_xauth_int_notify_callback(SshIkeNegotiation negotiation,
                                   SshIkePMPhaseII pm_info,
                                   SshIkeNotifyMessageType error_code,
                                   int number_of_attr_payloads,
                                   SshIkePayloadAttr *attributes,
                                   void *notify_callback_context)
{
  SshIkeXauthIntContext context = notify_callback_context;
  size_t username_len = 0, password_len = 0;
  unsigned char *username = NULL, *password = NULL;
  SshUInt32 value;
  SshIkeXauthType type = -1;

  if (error_code == SSH_IKE_NOTIFY_MESSAGE_CONNECTED)
    {
      if (number_of_attr_payloads != 1)
        {
          SSH_DEBUG(3, ("Xauth mode ends, "
                        "with number_of_attr_payloads != 1 = %d",
                        number_of_attr_payloads));
        }
      else if (attributes[0]->type != SSH_IKE_CFG_MESSAGE_TYPE_CFG_REPLY)
        {
          SSH_DEBUG(3, ("Xauth mode ends, with type != reply = %d",
                        attributes[0]->type));
        }
      else
        {
          int i;

          for (i = 0; i < attributes[0]->number_of_attributes; i++)
            {
              switch (attributes[0]->attributes[i].attribute_type)
                {
                case SSH_IKE_CFG_ATTR_XAUTH_TYPE:
                  if (type != -1)
                    SSH_DEBUG(3, ("Multiple TYPE parameters found"));
                  ssh_ike_get_data_attribute_int(&(attributes[0]->
                                                   attributes[i]),
                                                 &value,
                                                 0);
                  type = value;
                  break;
                case SSH_IKE_CFG_ATTR_XAUTH_USER_NAME:
                  if (password)
                    SSH_DEBUG(3, ("Multiple USER_NAME parameters found"));
                  username = attributes[0]->attributes[i].attribute;
                  username_len = attributes[0]->attributes[i].attribute_length;
                  break;
                case SSH_IKE_CFG_ATTR_XAUTH_USER_PASSWORD:
                  if (password)
                    SSH_DEBUG(3, ("Multiple USER_PASSWORD parameters found"));
                  password = attributes[0]->attributes[i].attribute;
                  password_len = attributes[0]->attributes[i].attribute_length;
                  break;
                case SSH_IKE_CFG_ATTR_XAUTH_PASSCODE:
                case SSH_IKE_CFG_ATTR_XAUTH_MESSAGE:
                case SSH_IKE_CFG_ATTR_XAUTH_CHALLENGE:
                case SSH_IKE_CFG_ATTR_XAUTH_DOMAIN:
                  SSH_DEBUG(3, ("Unknown attributes found type = %d",
                                attributes[0]->attributes[i].attribute_type));
                  break;
                }
            }
        }
    }
  else
    SSH_DEBUG(3, ("Xauth mode ends, with error code = %d", error_code));

  (*context->handler_callback)(negotiation, pm_info, error_code, type,
                               username, username_len,
                               password, password_len,
                               context->handler_callback_context);
  ssh_xfree(context);
}

/* Start xauth negotiation using authentication type that returns username and
   password. */
SshIkeErrorCode ssh_ike_connect_xauth_password(SshIkeServerContext context,
                                               SshIkeNegotiation *negotiation,
                                               SshIkeNegotiation
                                               isakmp_sa_negotiation,
                                               const char *remote_name,
                                               const char *remote_port,
                                               SshIkeXauthType type,
                                               void *policy_manager_data,
                                               int connect_flags,
                                               SshIkeXauthPasswordHandler
                                               handler_callback,
                                               void *handler_callback_context)
{
  SshIkeErrorCode err;
  SshIkePayloadAttr *attrs;
  unsigned char *p;
  SshIkeDataAttribute attr;
  SshIkeXauthIntContext new_context;

  new_context = ssh_xcalloc(1, sizeof(*new_context));

  new_context->handler_callback = handler_callback;
  new_context->handler_callback_context = handler_callback_context;

  attrs = ssh_xcalloc(1, sizeof(SshIkePayloadAttr));
  attrs[0] = ssh_xcalloc(1, sizeof(struct SshIkePayloadAttrRec));

  attrs[0]->type = SSH_IKE_CFG_MESSAGE_TYPE_CFG_REQUEST;
  attrs[0]->identifier = 0;
  attrs[0]->number_of_attributes = 0;
  attrs[0]->attributes =
    ssh_xcalloc(6, sizeof(struct SshIkeDataAttributeRec) + 50);
  attr = &(attrs[0]->attributes[0]);
  p = (unsigned char *) (attr + 6);

  attr->attribute_type = SSH_IKE_CFG_ATTR_XAUTH_TYPE;
  attr->attribute_length = 2;
  attr->attribute = p;
  SSH_PUT_16BIT(p, type);
  p += 2;
  attr++;
  attrs[0]->number_of_attributes++;

  attr->attribute_type = SSH_IKE_CFG_ATTR_XAUTH_USER_NAME;
  attr->attribute_length = 0;
  attr->attribute = p;
  attr++;
  attrs[0]->number_of_attributes++;

  attr->attribute_type = SSH_IKE_CFG_ATTR_XAUTH_USER_PASSWORD;
  attr->attribute_length = 0;
  attr->attribute = p;
  attr++;
  attrs[0]->number_of_attributes++;

  SSH_DEBUG(3, ("Xauth test starts"));

  err = ssh_ike_connect_cfg(context, negotiation, isakmp_sa_negotiation,
                            remote_name, remote_port,
                            1, attrs, policy_manager_data, connect_flags,
                            ike_xauth_int_notify_callback,
                            new_context);
  if (err != SSH_IKE_ERROR_OK)
    {
      ssh_xfree(new_context);
      ssh_xfree(attrs[0]->attributes);
      ssh_xfree(attrs[0]);
      ssh_xfree(attrs);
    }
  return err;
}

void ssh_policy_xauth_fill_attrs(SshIkePMPhaseII pm_info,
                                 SshIkePayloadAttr return_attribute,
                                 SshPolicyCfgFillAttrsCB callback_in,
                                 void *callback_context_in)
{
  SshIkePayloadAttr *attrs, attr;
  int i, j;
  SshIkeXauthType type = -1;
  SshUInt32 value;
  unsigned char *p;

  for (i = 0; i < return_attribute->number_of_attributes; i++)
    {
      if (return_attribute->attributes[i].attribute_type ==
          SSH_IKE_CFG_ATTR_XAUTH_TYPE)
        {
          if (!ssh_ike_get_data_attribute_int(&(return_attribute->
                                               attributes[i]),
                                             &value,
                                             0))
            {
              SSH_DEBUG(3,
                        ("Invalid xauth type (not representable in 32 bits)"));
              (*callback_in)(0, NULL, callback_context_in);
              return;
            }
          if (type != -1)
            {
              SSH_DEBUG(3, ("Xauth type given twice"));
              (*callback_in)(0, NULL, callback_context_in);
              return;
            }
          type = value;
        }
    }

  attrs = ssh_xcalloc(1, sizeof(*attrs));
  attr = attrs[0] = ssh_xcalloc(1, sizeof(struct SshIkePayloadAttrRec));
  /* Allocate attributes table, keep room for
     attribute structure and 20 bytes of data */
  attr->number_of_attributes = 0;
  attr->identifier = return_attribute->identifier;
  attr->attributes = ssh_xcalloc(return_attribute->number_of_attributes,
                                 sizeof(struct SshIkeDataAttributeRec) + 20);
  p = (unsigned char *) (&attr->attributes[return_attribute->
                                          number_of_attributes]);
  attr->type = SSH_IKE_CFG_MESSAGE_TYPE_CFG_REPLY;
  for (i = 0, j = 0; i < return_attribute->number_of_attributes; i++)
    {
      switch (return_attribute->attributes[i].attribute_type)
        {
        case SSH_IKE_CFG_ATTR_XAUTH_TYPE: /* Simple copy */
          attr->attributes[j].attribute_type =
            SSH_IKE_CFG_ATTR_XAUTH_TYPE;
          attr->attributes[j].attribute_length =
            return_attribute->attributes[i].attribute_length;
          attr->attributes[j].attribute = p;
          memcpy(p, return_attribute->attributes[i].attribute,
                 return_attribute->attributes[i].attribute_length);
          p += return_attribute->attributes[i].attribute_length;
          attr->number_of_attributes++;
          j++;
          break;
        case SSH_IKE_CFG_ATTR_XAUTH_USER_NAME:
          attr->attributes[j].attribute_type =
            SSH_IKE_CFG_ATTR_XAUTH_USER_NAME;
          attr->attributes[j].attribute_length = 8;
          attr->attributes[j].attribute = p;
          strcpy((char *) p, "koeerkki");
          p += 8;
          attr->number_of_attributes++;
          j++;
          break;
        case SSH_IKE_CFG_ATTR_XAUTH_USER_PASSWORD:
          attr->attributes[j].attribute_type =
            SSH_IKE_CFG_ATTR_XAUTH_USER_PASSWORD;
          attr->attributes[j].attribute_length = 8;
          attr->attributes[j].attribute = p;
          strcpy((char *) p, "password");
          p += 8;
          attr->number_of_attributes++;
          j++;
          break;
        case SSH_IKE_CFG_ATTR_XAUTH_PASSCODE:
        case SSH_IKE_CFG_ATTR_XAUTH_MESSAGE:
        case SSH_IKE_CFG_ATTR_XAUTH_CHALLENGE:
        case SSH_IKE_CFG_ATTR_XAUTH_DOMAIN:
          /* Nothing to known yet */
          break;
        }
    }
  (*callback_in)(1, attrs, callback_context_in);
}

#endif /* SSHDIST_ISAKMP_CFG_MODE */
