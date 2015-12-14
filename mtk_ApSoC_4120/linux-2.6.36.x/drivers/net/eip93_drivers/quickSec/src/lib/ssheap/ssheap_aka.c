/*
  ssheap_aka.c

  Copyright:
          Copyright (c) 2002-2007 SFNT Finland Oy.
  All Rights Reserved.
*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshcrypt.h"
#include "ssheap.h"
#include "ssheapi.h"
#include "ssheap_packet.h"
#include "ssheap_aka.h"

#define SSH_DEBUG_MODULE "SshEapAka"

#ifdef SSHDIST_EAP_AKA

/********************* Forward Declarations ****************************/
static void 
ssh_eap_aka_auth_reject(SshEapProtocol protocol,
                        SshEap eap,
                        SshBuffer buf);






	
static SshUInt8
ssh_eap_aka_decode_identity(SshEapProtocol protocol, 
                            SshBuffer buf)
{
  SshUInt8  id_cnt      = 0;
  SshUInt16 offset      = 8;
  SshEapAkaState state  = NULL;
  
  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(buf != NULL);

  state = ssh_eap_protocol_get_state(protocol);
  
  state->identity_msg_cnt++;

  if (state->identity_msg_cnt > SSH_EAP_AKA_MAX_IDENTITY_MSGS)
    return SSH_EAP_AKA_ERR_INVALID_STATE;

  /* RFC 4187 prohibits sending any more identity requests 
     if permanent ID request has already been received. */
  if (state->aka_proto_flags & SSH_EAP_AKA_PERMID_RCVD)
    return SSH_EAP_AKA_ERR_INVALID_STATE;

  for (; offset < ssh_buffer_len(buf) && 
         SSH_EAP_AT_LEN(buf, offset); )
    { 
      switch(ssh_buffer_ptr(buf)[offset])
	{
        case SSH_EAP_AT_ANY_ID_REQ:

          if (state->aka_proto_flags & SSH_EAP_AKA_FULLID_RCVD ||
              state->aka_proto_flags & SSH_EAP_AKA_ANYID_RCVD)
            return SSH_EAP_AKA_ERR_INVALID_STATE;
          
          state->aka_proto_flags |= SSH_EAP_AKA_ANYID_RCVD;

          offset += SSH_EAP_AT_LEN(buf, offset);
	  id_cnt++;
          break;

	case SSH_EAP_AT_FULLAUTH_ID_REQ:
          
          if (state->aka_proto_flags & SSH_EAP_AKA_FULLID_RCVD)
            return SSH_EAP_AKA_ERR_INVALID_STATE;
          
          state->aka_proto_flags |= SSH_EAP_AKA_FULLID_RCVD;

          offset += SSH_EAP_AT_LEN(buf, offset);
	  id_cnt++;
          break;

	case SSH_EAP_AT_PERMANENT_ID_REQ:
          
          state->aka_proto_flags |= SSH_EAP_AKA_PERMID_RCVD;

	  offset += SSH_EAP_AT_LEN(buf, offset);
	  id_cnt++;
	  break;
	
	default:
          if (ssh_buffer_ptr(buf)[offset] > 127 &&
              ssh_buffer_ptr(buf)[offset] < 256)
            {
              offset += SSH_EAP_AT_LEN(buf, offset);
              SSH_DEBUG(SSH_D_FAIL, ("eap aka skippable attribute detected"
                                     " (ie %x)", ssh_buffer_ptr(buf)[offset]));
              break;
            }

          SSH_DEBUG(SSH_D_FAIL, ("eap aka invalid ie detected (ie %x)", 
                                 ssh_buffer_ptr(buf)[offset]));
	  return SSH_EAP_AKA_ERR_INVALID_IE;
	}
    }

  state->aka_proto_flags |= SSH_EAP_AKA_ANYID_RCVD;

  if (offset != ssh_buffer_len(buf))
    return SSH_EAP_AKA_ERR_PACKET_CORRUPTED;

  if (id_cnt == 1) 
    return SSH_EAP_AKA_DEC_OK;

  return SSH_EAP_AKA_ERR_GENERAL; 
}

static SshUInt8
ssh_eap_aka_decode_challenge(SshEapProtocol protocol, 
			     SshBuffer buf, 
                             unsigned char *rand,
                             unsigned char *autn)
{
  SshUInt8  mac_found     = 0;
  SshUInt8  ativ_cnt      = 0;
  SshUInt8  check_cnt     = 0;
  SshUInt8  autn_cnt      = 0;
  SshUInt8  encrdata_cnt  = 0;
  SshUInt8  rand_found    = 0;
  SshUInt8  resultind_cnt = 0;
  SshUInt8  bidding_cnt   = 0;
  SshUInt16 bidding_val   = 0;
  SshUInt16 offset        = 8;
  SshEapAkaState state    = NULL;
  
  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(buf != NULL);
  SSH_ASSERT(rand != NULL);
  SSH_ASSERT(autn != NULL);
  
  state = ssh_eap_protocol_get_state(protocol);
    
  for (; offset < ssh_buffer_len(buf) &&
         SSH_EAP_AT_LEN(buf, offset); )
    { 
      switch(ssh_buffer_ptr(buf)[offset])
	{
	case SSH_EAP_AT_IV:
	  
          ativ_cnt++;
	  offset += SSH_EAP_AT_LEN(buf, offset);
	  break;

	case SSH_EAP_AT_ENCR_DATA:
 
          encrdata_cnt++;
	  offset += SSH_EAP_AT_LEN(buf, offset);
	  break;

        case SSH_EAP_AT_CHECKCODE:
          
          check_cnt++;
          SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka server requested checkcode"));
          break;
          
	case SSH_EAP_AT_RESULT_IND:

	  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka server indicated it want's" 
                                       " to use protected success messages"));
	  
          resultind_cnt++;

	  state->aka_proto_flags |= SSH_EAP_AKA_PROT_SUCCESS;
	  offset += SSH_EAP_AT_LEN(buf, offset);
	  break;
                     
	case SSH_EAP_AT_MAC:
	  
	  if ((ssh_buffer_ptr(buf)[offset + 1] & 0xFF) != 5)
	    return SSH_EAP_AKA_ERR_INVALID_IE;
          
	  offset += SSH_EAP_AT_LEN(buf, offset);
          mac_found++;
	  break;

        case SSH_EAP_AT_AUTN:

          autn_cnt++;
          if ((SSH_EAP_AT_LEN(buf, offset) + offset) > ssh_buffer_len(buf) ||
              SSH_EAP_AT_LEN(buf, offset) != 20)
	    {
	      return SSH_EAP_AKA_ERR_PACKET_CORRUPTED;
	    }
          
          memcpy(autn, &ssh_buffer_ptr(buf)[offset + 4], 
                 SSH_EAP_AKA_AUTN_LEN);
          offset += SSH_EAP_AT_LEN(buf, offset);

          break;

	case SSH_EAP_AT_RAND:
          
          rand_found++;
          if ((SSH_EAP_AT_LEN(buf, offset) + offset) > ssh_buffer_len(buf) ||
              SSH_EAP_AT_LEN(buf, offset) != 20)
	    {
	      return SSH_EAP_AKA_ERR_PACKET_CORRUPTED;
	    }
          
          memcpy(rand, &ssh_buffer_ptr(buf)[offset + 4], 
                 SSH_EAP_AKA_RAND_LEN);
          offset += SSH_EAP_AT_LEN(buf, offset);
	  break;

	case SSH_EAP_AT_BIDDING:

	  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka server sent us AT_BIDDING "));
	  bidding_cnt++;

          /* If multiple bidding attribute is sent from server in the 
             challenge message, this case will be treated as error. */
	  if (bidding_cnt > 1)
            return SSH_EAP_AKA_ERR_GENERAL;

          /* Check the attribute length is 4 bytes */
	  if (SSH_EAP_AT_LEN(buf, offset) != 4)
            return SSH_EAP_AKA_ERR_PACKET_CORRUPTED;

          /* Check that the Length field of the attribute is 1(MUST) */
  	  if ((ssh_buffer_ptr(buf)[offset + 1] & 0xFF) != 1)
  	    return SSH_EAP_AKA_ERR_INVALID_IE;

  	  state->aka_proto_flags |= SSH_EAP_AKA_BIDDING_REQ_RCVD;

	  bidding_val = ((ssh_buffer_ptr(buf)[offset + 2] & 0xff) << 8) |
			 (ssh_buffer_ptr(buf)[offset + 3] & 0xff);
	  	  
          /* Check whether server indicated us to use the AKA-DASH, and 
             prefers it over AKA */
  	  if (bidding_val & 8000)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                              ("eap aka server indicated it's willing"
                               " to use AKA-DASH, and prefers it over AKA"));
              /* Check do we support AKA-DASH */
              if (state->transform & SSH_EAP_TRANSFORM_PRF_HMAC_SHA256)
                return SSH_EAP_AKA_ERR_USE_AKA_DASH;
            }

          offset += SSH_EAP_AT_LEN(buf, offset);
  	  break;

	default:
          if (ssh_buffer_ptr(buf)[offset] > 127 &&
              ssh_buffer_ptr(buf)[offset] < 256)
            {
              offset += SSH_EAP_AT_LEN(buf, offset);
              SSH_DEBUG(SSH_D_FAIL, ("eap aka skippable attribute detected"
                                     " (ie %x)", ssh_buffer_ptr(buf)[offset]));
              break;
            }


	  SSH_DEBUG(SSH_D_FAIL, ("eap aka invalid ie detected (ie %x)", 
				  ssh_buffer_ptr(buf)[offset]));
	  return SSH_EAP_AKA_ERR_INVALID_IE;
	}
    }

  if (offset != ssh_buffer_len(buf))
    return SSH_EAP_AKA_ERR_PACKET_CORRUPTED;

  if (ativ_cnt > 1 || encrdata_cnt > 1 || resultind_cnt > 1 ||
      autn_cnt > 1 || check_cnt > 1 || bidding_cnt > 1)
    return SSH_EAP_AKA_ERR_GENERAL;

  if (mac_found == 1 && rand_found == 1) 
    return SSH_EAP_AKA_DEC_OK;

  return SSH_EAP_AKA_ERR_GENERAL;
}

#ifdef SSHDIST_EAP_AKA_DASH
static void 
ssh_eap_aka_dash_send_challenge_alt_kdf(SshEapProtocol protocol,
                                        SshEap eap, SshBuffer buffer)
{
  SshEapAkaState state     = NULL;
  SshBuffer      pkt       = NULL;
  SshUInt8       buf[7]    = "";
  SshUInt16      kdf_val   = SSH_EAP_KDF_FAIL;
  SshUInt16      pkt_len   = SSH_EAP_AKA_DASH_CHALLENGE_ALT_KDF_REPLY_LEN;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);
             
  SSH_DEBUG(SSH_D_NICETOKNOW, 
  	("eap aka-dash sending alternate kdf suggestion to server"));
  
  state = ssh_eap_protocol_get_state(protocol);

  /* We support only the SSH_EAP_KDF_SHA256 */
  kdf_val = state->use_kdf;
  SSH_ASSERT(kdf_val != SSH_EAP_KDF_FAIL);

  /* Construct 5 bytes out of 8 bytes of the EAP Header */
  pkt = ssh_eap_create_reply(eap, (SshUInt16)(pkt_len - 5), 
                             protocol->impl->id);
  if (!pkt)
    {
      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }

  /* 3 bytes Subtype and Reserved fields in the EAP header */
  buf[0] = SSH_EAP_AKA_CHALLENGE;
  buf[1] = buf[2] = 0;
  
  /* 4 bytes for the AT_KDF */
  buf[3] = SSH_EAP_AT_KDF;
  buf[4] = 1; /* For AT_KDF is always 1 */
  buf[5] = (kdf_val & 0xFF00) >> 8;
  buf[6] = (kdf_val & 0xFF);

  if (ssh_buffer_append(pkt, buf, 7) != SSH_BUFFER_OK)
    {
      ssh_buffer_free(pkt);
      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }
  
  ssh_eap_protocol_send_response(protocol, eap, pkt);

  /* Keep the track of this response */
  state->aka_proto_flags |= SSH_EAP_AKA_DASH_CHALLENGE_KDF_ALT_SENT;
}

static SshUInt8
ssh_eap_aka_dash_select_kdf(SshEapProtocol protocol, 
                            SshBuffer buf,
                            Boolean verify_alt_kdf)
{
  SshUInt8 no_match          = 1;
  SshUInt8 found_duplicates  = 0;
  SshUInt8 atkdf_cnt         = 0;
  SshUInt16 pkt_kdf_val      = 0;
  SshUInt16 buf_kdf_val      = 0;
  SshUInt16 pkt_offset       = 8;
  SshUInt16 next_offset      = 8;
  SshUInt16 offset           = 8;
  SshBuffer pkt              = NULL;
  SshEapAkaState state       = NULL;
  Boolean first_match        = FALSE;
  Boolean alt_match          = FALSE; 

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(buf != NULL);

  state = ssh_eap_protocol_get_state(protocol);

  pkt = buf;

  /* Search for supported transform in buf, if found any duplicates, 
     report error */

  /* Outer FOR loop */
  for (; offset < ssh_buffer_len(buf) && SSH_EAP_AT_LEN(buf, offset);
	 offset += SSH_EAP_AT_LEN(buf, offset))
    {
      /* Store the next_offset and assign it to the pkt_offset */
      next_offset += SSH_EAP_AT_LEN(buf, offset);
     
      /* Update the pkt_offset for inner search */
      pkt_offset = next_offset;

      if (ssh_buffer_ptr(buf)[offset] == SSH_EAP_AT_KDF)
        {
          /* Count the at_kdf, this shall be used for first_match */
          atkdf_cnt++; 

          /* Sanity checking of the attribute */

          /* Check the attribute length is 4 bytes */
          if (SSH_EAP_AT_LEN(buf, offset) != 4)
            return SSH_EAP_AKA_ERR_PACKET_CORRUPTED;
	  
          /* Check that the Length field of the attribute is 1(MUST)*/
          if ((ssh_buffer_ptr(buf)[offset + 1] & 0xFF) != 1)
            return SSH_EAP_AKA_ERR_INVALID_IE;
          
          /* Get the enumerated kdf value from attribute */
          buf_kdf_val = ((ssh_buffer_ptr(buf)[offset + 2] & 0xff) << 8) |
                	 (ssh_buffer_ptr(buf)[offset + 3] & 0xff);

	  /* Inner FOR loop */
          for (; pkt_offset < ssh_buffer_len(pkt) &&
                 SSH_EAP_AT_LEN(pkt, pkt_offset); 
                 pkt_offset += SSH_EAP_AT_LEN(buf, offset))
            {
              if (ssh_buffer_ptr(pkt)[pkt_offset] == SSH_EAP_AT_KDF)
                {
                  /* Check the attribute length is 4 bytes */
                  if (SSH_EAP_AT_LEN(pkt, pkt_offset) != 4)
                    return SSH_EAP_AKA_ERR_PACKET_CORRUPTED;

                  /* Check that the Length field of the attribute is 1(MUST)*/
                  if ((ssh_buffer_ptr(pkt)[pkt_offset + 1] & 0xFF) != 1)
                    return SSH_EAP_AKA_ERR_INVALID_IE;
          
                  /* Get the enumerated kdf value from attribute for checking
                     the duplicates */
                  pkt_kdf_val = 
                        ((ssh_buffer_ptr(pkt)[pkt_offset + 2] & 0xff) << 8) |
                 	 (ssh_buffer_ptr(pkt)[pkt_offset + 3] & 0xff);

                  SSH_DEBUG(SSH_D_LOWOK, ("pkt_kdf_val: %d", pkt_kdf_val));
 
                  /* Matching the default algorithm sugggested by 3GPP */
                  if (buf_kdf_val == SSH_EAP_KDF_SHA256)
                    {
                      if (state->transform & SSH_EAP_TRANSFORM_PRF_HMAC_SHA256)
                        {
                          SSH_DEBUG(SSH_D_LOWOK,
					  ("Found a matching transform"));

                          state->use_kdf = buf_kdf_val;

                          /* We have atleast some match, unset no_match */
		          no_match = 0;
			  
                          /* Did we match the first one ? if yes, set 
                             first_match otherwise dont set */
                          if (atkdf_cnt == 1)
			    {
                              /* Found the first match */
                              first_match = TRUE;
			    }
                          else if (atkdf_cnt > 1)
                            {
                              /* Found the match in alternate AT_KDFs */
                              alt_match = TRUE;
                            }
                        }
                    }
	      
                  /* Check the duplicates of same buf_kdf_val in other 
                     AT_KDFs (pkt_kdf_val) */
                  if (buf_kdf_val == pkt_kdf_val)
                    {
                      SSH_DEBUG(SSH_D_FAIL, ("Found duplicate AT_KDF values: \
                                          %d %d", buf_kdf_val, pkt_kdf_val));

                      /* We have atleast some match, unset no_match */
		      no_match = 0;

                      /* We found the duplicates */
                      found_duplicates = 1;
		      break;
                    }
                }
            } /* End of the inner FOR loop */
        }
      if (found_duplicates)
        break;
    } /* End of the outer FOR loop */

  /* Duplicates kdf values are allowed only in one special case, wherein,
     we have suggested the server to resend the challenge with our
     preferred kdf in the first place along with previous list. For example,
     initial list(IL) sent by server was
     IL = {at_kdf[2], at_kdf[1], at_kdf[3],...}.
     After our suggested kdf[1], server sents us IL which appears as
     IL = {at_kdf[1], at_kdf[2], at_kdf[1], at_kdf[3],...}.
     This condition is verified only when we have verify_alt_kdf set as TRUE */
  if ((verify_alt_kdf == TRUE) && (first_match == TRUE) &&
      (alt_match == TRUE) && found_duplicates)
    return SSH_EAP_AKA_DASH_KDF_FIRST_MATCH;
  /* Server didnt accepted our kdf suggestion, let us fail the authentication
   * as if AUTN INCORRECT */
  else if ((verify_alt_kdf == TRUE) && (first_match == FALSE))
    return SSH_EAP_AKA_DASH_KDF_NO_MATCH;

  /* First check the duplicate error condition */
  if (found_duplicates)
    return SSH_EAP_AKA_ERR_GENERAL;

  /* No matches, we will not able to calculate the keys. 
     Hence, fails as AUTN incorrect */
  if (no_match)
    return SSH_EAP_AKA_DASH_KDF_NO_MATCH;

  /* Return, First match */
  if (!found_duplicates && !no_match && (first_match == TRUE))
    return SSH_EAP_AKA_DASH_KDF_FIRST_MATCH;

  /* Return, Alternate match */
  if (!found_duplicates && !no_match && (first_match == FALSE)
      && (alt_match == TRUE))
    return SSH_EAP_AKA_DASH_KDF_ALT_MATCH;
  
  return SSH_EAP_AKA_DASH_KDF_NO_MATCH;
}

static SshUInt8
ssh_eap_aka_dash_decode_challenge(SshEapProtocol protocol, 
                                  SshBuffer buf, 
                                  unsigned char *rand,
                                  unsigned char *autn)
{
  SshUInt8  mac_found      = 0;
  SshUInt8  ativ_cnt       = 0;
  SshUInt8  check_cnt      = 0;
  SshUInt8  autn_cnt       = 0;
  SshUInt8  encrdata_cnt   = 0;
  SshUInt8  rand_found     = 0;
  SshUInt8  resultind_cnt  = 0;
  SshUInt8  kdfinput_found = 0;
  SshUInt8  atkdf_cnt      = 0;
  SshUInt8  rval           = 0;
  SshUInt16 offset         = 8;
  SshEapAkaState state     = NULL;
  
  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(buf != NULL);
  SSH_ASSERT(rand != NULL);
  SSH_ASSERT(autn != NULL);
  
  state = ssh_eap_protocol_get_state(protocol);
    
  for (; offset < ssh_buffer_len(buf) &&
         SSH_EAP_AT_LEN(buf, offset); )
    { 
      switch(ssh_buffer_ptr(buf)[offset])
	{
	case SSH_EAP_AT_IV:
	  
          ativ_cnt++;
	  offset += SSH_EAP_AT_LEN(buf, offset);
	  break;

	case SSH_EAP_AT_ENCR_DATA:
 
          encrdata_cnt++;
	  offset += SSH_EAP_AT_LEN(buf, offset);
	  break;

        case SSH_EAP_AT_CHECKCODE:
          
          check_cnt++;
          SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka server requested checkcode"));
          break;
          
	case SSH_EAP_AT_RESULT_IND:

	  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka server indicated it want's" 
                                       " to use protected success messages"));
	  
          resultind_cnt++;

	  state->aka_proto_flags |= SSH_EAP_AKA_PROT_SUCCESS;
	  offset += SSH_EAP_AT_LEN(buf, offset);
	  break;
                     
	case SSH_EAP_AT_MAC:
	  
	  if ((ssh_buffer_ptr(buf)[offset + 1] & 0xFF) != 5)
	    return SSH_EAP_AKA_ERR_INVALID_IE;
          
	  offset += SSH_EAP_AT_LEN(buf, offset);
          mac_found++;
	  break;

        case SSH_EAP_AT_AUTN:

          autn_cnt++;
          if ((SSH_EAP_AT_LEN(buf, offset) + offset) > ssh_buffer_len(buf) ||
              SSH_EAP_AT_LEN(buf, offset) != 20)
	    {
	      return SSH_EAP_AKA_ERR_PACKET_CORRUPTED;
	    }
          
          memcpy(autn, &ssh_buffer_ptr(buf)[offset + 4], 
                 SSH_EAP_AKA_AUTN_LEN);
          offset += SSH_EAP_AT_LEN(buf, offset);

          break;

	case SSH_EAP_AT_RAND:
          
          rand_found++;
          if ((SSH_EAP_AT_LEN(buf, offset) + offset) > ssh_buffer_len(buf) ||
              SSH_EAP_AT_LEN(buf, offset) != 20)
	    {
	      return SSH_EAP_AKA_ERR_PACKET_CORRUPTED;
	    }
          
          memcpy(rand, &ssh_buffer_ptr(buf)[offset + 4], 
                 SSH_EAP_AKA_RAND_LEN);
          offset += SSH_EAP_AT_LEN(buf, offset);
	  break;

	case SSH_EAP_AT_KDF_INPUT:
         
          /* Keep track of the AT_KDF_INPUT count */
          kdfinput_found++;

          /* Sanity checking of the attribute */
          if ((SSH_EAP_AT_LEN(buf, offset) + offset) > ssh_buffer_len(buf))
            return SSH_EAP_AKA_ERR_PACKET_CORRUPTED;
          
          state->network_name_len = 
                  ((ssh_buffer_ptr(buf)[offset + 2] & 0xff) << 8) |
                  (ssh_buffer_ptr(buf)[offset + 3] & 0xff);

	  /* Network name cannot be of zero length, if network name length is
             zero then, assume as AUTN incorrect */
	  if (state->network_name_len == 0)
            return SSH_EAP_AKA_DASH_ERR_AUTN_INCORRECT;

          /* Wipe out old stuff if required */
          if (state->network_name)
            {
              ssh_buffer_free(state->network_name);
	      state->network_name = NULL;
            }

	  /* Allocate memory for the network_name */
          if (!(state->network_name = ssh_buffer_allocate()))
            return SSH_EAP_AKA_ERR_MEMALLOC_FAILED;

          /* Copy the network name from the AT_KDF_INPUT */
          if (ssh_buffer_append(state->network_name, 
                                &ssh_buffer_ptr(buf)[offset + 4],
                                state->network_name_len) != SSH_BUFFER_OK)
            {
              ssh_buffer_free(state->network_name);
              state->network_name = NULL;
              return SSH_EAP_AKA_ERR_MEMALLOC_FAILED;
            }

          offset += SSH_EAP_AT_LEN(buf, offset);
          break;

        case SSH_EAP_AT_KDF:

          /* There could be many AT_KDFs in the challenge */
          atkdf_cnt++;

          /* We are processing all the AT_KDFs in the routine 
             ssh_eap_aka_dash_select_kdf(). Ignore the processing
             of the AT_KDFs if atkdf_cnt > 1, since we have already
             done that in ssh_eap_aka_dash_select_kdf(). Otherwise, we
             are just counting the atkdfs */
          if (atkdf_cnt == 1)
	    {
              /* We have sent response to server for re-sending the 
                 challenge with our preferred AT_KDF in first position.
                 Let us check whether server did what we said */
              if ((state->aka_proto_flags & 
                          SSH_EAP_AKA_DASH_CHALLENGE_KDF_ALT_SENT) && 
                  !(state->aka_proto_flags &
                           SSH_EAP_AKA_DASH_CHALLENGE_KDF_ALT_RCVD))
	        {
                  rval = ssh_eap_aka_dash_select_kdf(protocol, buf, TRUE);
		  state->aka_proto_flags |= 
                                   SSH_EAP_AKA_DASH_CHALLENGE_KDF_ALT_RCVD;
                }
	      /* First time we received the challenge */
              else if (!(state->aka_proto_flags & 
                                (SSH_EAP_AKA_DASH_CHALLENGE_KDF_ALT_SENT |
				 SSH_EAP_AKA_DASH_CHALLENGE_KDF_ALT_RCVD)))
                {
                  rval = ssh_eap_aka_dash_select_kdf(protocol, buf, FALSE);
                }
	    }
	  break;

	default:

	  SSH_DEBUG(SSH_D_FAIL, ("eap aka-dash invalid ie detected (ie %x)", 
				  ssh_buffer_ptr(buf)[offset]));
	  return SSH_EAP_AKA_ERR_INVALID_IE;
	}
    }

  if (offset != ssh_buffer_len(buf))
    return SSH_EAP_AKA_ERR_PACKET_CORRUPTED;

  if (ativ_cnt > 1 || encrdata_cnt > 1 || resultind_cnt > 1 ||
      autn_cnt > 1 || check_cnt > 1 || kdfinput_found > 1)
    return SSH_EAP_AKA_ERR_GENERAL;

  /* AT_KDF or AT_KDF_INPUT is missing in the challenge received
     leads to fail the authentication as we are not in position 
     to calculate the keys. */
  if (atkdf_cnt == 0 || kdfinput_found == 0)
    return SSH_EAP_AKA_DASH_ERR_AUTN_INCORRECT;

  /* Processing the rval from the ssh_eap_aka_dash_select_kdf() */
  switch (rval)
    {
    case SSH_EAP_AKA_ERR_PACKET_CORRUPTED:

      return SSH_EAP_AKA_ERR_PACKET_CORRUPTED;
      break;

    case SSH_EAP_AKA_ERR_INVALID_IE:

      return SSH_EAP_AKA_ERR_INVALID_IE;
      break;

    case SSH_EAP_AKA_ERR_GENERAL:

      return SSH_EAP_AKA_ERR_GENERAL;
      break;

    case SSH_EAP_AKA_DASH_KDF_FIRST_MATCH:

      /* We should be sure at this point we have a valid KDF for
         calculating the keys */
      SSH_ASSERT(state->use_kdf != SSH_EAP_KDF_FAIL);
      if (state->aka_proto_flags & 
          (SSH_EAP_AKA_DASH_CHALLENGE_KDF_ALT_SENT |
	   SSH_EAP_AKA_DASH_CHALLENGE_KDF_ALT_RCVD))
	SSH_DEBUG(SSH_D_NICETOKNOW, ("Server accepted our alternate kdf"
                                     "suggestion: %d", state->use_kdf));
      break;

    case SSH_EAP_AKA_DASH_KDF_NO_MATCH:
      
      if (state->aka_proto_flags & 
          (SSH_EAP_AKA_DASH_CHALLENGE_KDF_ALT_SENT |
	   SSH_EAP_AKA_DASH_CHALLENGE_KDF_ALT_RCVD))
	SSH_DEBUG(SSH_D_NICETOKNOW, ("Server didn't accepted our alternate"
                                     "kdf suggestion: %d", state->use_kdf));
      /* No match case results into AUTN incorrect, Authentication
         Reject case. */
      return SSH_EAP_AKA_DASH_ERR_AUTN_INCORRECT;
      break;

    case SSH_EAP_AKA_DASH_KDF_ALT_MATCH:

      /*  Let us ask the server to re-send the challenge with our 
          preferred AT_KDF in first position. */
      return SSH_EAP_AKA_DASH_ERR_ALT_KDF;
      break;
      
    default:

      /* We are not returning anything from default case because,
         later in the code we handle that. */
      SSH_DEBUG(SSH_D_FAIL, ("Invalid rval detected (ie %d)",rval));
      break;
    }

  if (mac_found == 1 && rand_found == 1 &&
      kdfinput_found == 1 && atkdf_cnt >= 1)
    return SSH_EAP_AKA_DEC_OK;

  return SSH_EAP_AKA_ERR_GENERAL;
}
#endif /* SSHDIST_EAP_AKA_DASH */

static SshUInt8
ssh_eap_aka_decode_notification(SshEapProtocol protocol, 
                                SshBuffer buf,
                                SshUInt16 *notif_val)
{
  SshUInt8  mac_cnt       = 0;
  SshUInt8  ativ_cnt      = 0;
  SshUInt8  notif_cnt     = 0;
  SshUInt8  counter_cnt   = 0;
  SshUInt8  encrdata_cnt  = 0;
  SshUInt16 offset        = 8;
  
  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(buf != NULL);
  SSH_ASSERT(notif_val != NULL);

  for (; offset < ssh_buffer_len(buf) &&
         SSH_EAP_AT_LEN(buf, offset); )
    { 
      switch(ssh_buffer_ptr(buf)[offset])
	{
	case SSH_EAP_AT_IV:
	  
          ativ_cnt++;
	  offset += SSH_EAP_AT_LEN(buf, offset);
	  break;

	case SSH_EAP_AT_ENCR_DATA:
	  
          encrdata_cnt++;
	  offset += SSH_EAP_AT_LEN(buf, offset);
	  break;

	case SSH_EAP_AT_MAC:
 
          mac_cnt++;
	  if ((ssh_buffer_ptr(buf)[offset + 1] & 0xFF) != 5)
	    return SSH_EAP_AKA_ERR_INVALID_IE;

	  offset += SSH_EAP_AT_LEN(buf, offset);
	  break;

	case SSH_EAP_AT_COUNTER:

          counter_cnt++;
	  offset += SSH_EAP_AT_LEN(buf, offset);
	  break;

        case SSH_EAP_AT_NOTIFICATION:

          notif_cnt++;
          if (SSH_EAP_AT_LEN(buf, offset) != 4)
            return SSH_EAP_AKA_ERR_INVALID_IE;
           
          *notif_val = ((ssh_buffer_ptr(buf)[offset + 2] & 0xff) << 8) |
                         (ssh_buffer_ptr(buf)[offset + 3] & 0xff);

	  offset += SSH_EAP_AT_LEN(buf, offset);
          break;

	default:
          if (ssh_buffer_ptr(buf)[offset] > 127 &&
              ssh_buffer_ptr(buf)[offset] < 255)
            {
              offset += SSH_EAP_AT_LEN(buf, offset);
              SSH_DEBUG(SSH_D_FAIL, ("eap aka skippable attribute detected"
                                     " (ie %x)", ssh_buffer_ptr(buf)[offset]));
              break;
            }

	  SSH_DEBUG(SSH_D_FAIL, ("eap aka invalid ie detected (%x)", 
				  ssh_buffer_ptr(buf)[offset]));
	  return SSH_EAP_AKA_ERR_INVALID_IE;
	}
    }

  if (offset != ssh_buffer_len(buf))
    return SSH_EAP_AKA_ERR_PACKET_CORRUPTED;

  if (ativ_cnt > 1 || encrdata_cnt > 1 || mac_cnt > 1 || 
      counter_cnt > 1 || notif_cnt > 1)
    return SSH_EAP_AKA_ERR_GENERAL;

  if (notif_cnt == 1)
    return SSH_EAP_AKA_DEC_OK;

  return SSH_EAP_AKA_ERR_GENERAL;
}

static void 
ssh_eap_aka_send_client_error(SshEapProtocol protocol, SshEap eap,
                              SshUInt16 err_code)
{
  SshBuffer pkt     = NULL;
  SshUInt16 pkt_len = SSH_EAP_AKA_CLIENT_ERROR_REPLY_LEN;
  SshUInt8  buf[7] = "";

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);

  pkt = ssh_eap_create_reply(eap, (SshUInt16)(pkt_len - 5), 
                             protocol->impl->id);
  if (!pkt)
    {
      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }

  buf[0] = SSH_EAP_CLIENT_ERROR;
  buf[1] = buf[2] = 0;
  
  buf[3] = SSH_EAP_AT_CLIENT_ERROR_CODE;
  buf[4] = 1;
  buf[5] = (err_code & 0xFF00) >> 8;
  buf[6] = (err_code & 0xFF);

  if (ssh_buffer_append(pkt, buf, 7) != SSH_BUFFER_OK)
    {
      ssh_buffer_free(pkt);
      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }

  ssh_eap_protocol_send_response(protocol, eap, pkt);
}

/* Handle all possible error cases here. In short, all errors are 
   treated as fatal and always terminate authentication. */
static void
ssh_eap_aka_client_error(SshEapProtocol protocol, SshEap eap,
                         SshUInt8 error)
{
  SshEapAkaState state;
  
  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka processing client error of type"
                               " %u", error));

  state = ssh_eap_protocol_get_state(protocol);
  state->aka_proto_flags |= SSH_EAP_AKA_STATE_FAILED;

  switch(error)
    {
      /* We shouldn't be entering here with these values. */
    case SSH_EAP_AKA_DEC_OK:

      SSH_ASSERT(0);
      break;

    case SSH_EAP_AKA_ERR_GENERAL:         
    case SSH_EAP_AKA_ERR_INVALID_IE:
    case SSH_EAP_AKA_ERR_PACKET_CORRUPTED:
    case SSH_EAP_AKA_ERR_MEMALLOC_FAILED:
    case SSH_EAP_AKA_ERR_INVALID_STATE:

      ssh_eap_aka_send_client_error(protocol, eap, 0);
      break;

      /* Don't wan't to get here either. */
    default:

      SSH_ASSERT(0);
      break;
    }
  
  /* Inform the upper layer that something has gone bad here. */
  ssh_eap_protocol_auth_fail(protocol, eap,
                             SSH_EAP_SIGNAL_AUTH_FAIL_REPLY, NULL);
}

static void
ssh_eap_aka_send_identity_reply(SshEapProtocol protocol,
                                SshEap eap)
{
  SshEapAkaState state   = NULL;
  SshBuffer      pkt     = NULL;
  SshUInt8       buf[3]  = "";
  SshUInt16      pkt_len = SSH_EAP_AKA_IDENTITY_REPLY_LEN;
  
  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka sending identity reply"));

  state = ssh_eap_protocol_get_state(protocol);
  
  /* Calculate the real packet length. */
  if (state->user_len % 4)
    pkt_len += 4 + state->user_len + (4 - (state->user_len % 4));
  else
    pkt_len += 4 + state->user_len;
  
  pkt = ssh_eap_create_reply(eap, (SshUInt16)(pkt_len - 5), 
                             protocol->impl->id);
  if (!pkt)
    {
      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }
  
  buf[0] = SSH_EAP_AKA_IDENTITY;
  buf[1] = buf[2] = 0;
  
  if (ssh_buffer_append(pkt, buf, 3) != SSH_BUFFER_OK)
    {
      ssh_buffer_free(pkt);

      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }
  
  if (!ssh_eap_packet_append_identity_attr(pkt, 
                                           ssh_buffer_ptr(state->user), 
                                           state->user_len))
    {
      ssh_buffer_free(pkt);

      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }

  ssh_eap_protocol_send_response(protocol, eap, pkt);
}

static void
ssh_eap_aka_send_synch_fail_reply(SshEapProtocol protocol,
                                  SshEap eap)
{
  SshEapAkaState state   = NULL;
  SshBuffer      pkt     = NULL;
  SshUInt8       buf[3]  = "";
  SshUInt16      pkt_len = SSH_EAP_AKA_SYNCH_REPLY_LEN;
  
  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka sending synchronisation "
                               "failed reply"));

  state = ssh_eap_protocol_get_state(protocol);
  
  pkt = ssh_eap_create_reply(eap, (SshUInt16)(pkt_len - 5), 
                             protocol->impl->id);
  if (!pkt)
    {
      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }
  
  buf[0] = SSH_EAP_AKA_SYNCH_FAILURE;
  buf[1] = buf[2] = 0;

  if (ssh_buffer_append(pkt, buf, 3) != SSH_BUFFER_OK)
    {
      ssh_buffer_free(pkt);

      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }
  
  if (!ssh_eap_packet_append_auts_attr(pkt, state->aka_id.auts))
    {
      ssh_buffer_free(pkt);

      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }

  ssh_eap_protocol_send_response(protocol, eap, pkt);
}

static void
ssh_eap_aka_send_auth_reject_reply(SshEapProtocol protocol,
                                   SshEap eap)
{
  SshBuffer      pkt     = NULL;
  SshUInt8       buf[3]  = "";
  SshUInt16      pkt_len = SSH_EAP_AKA_AUTH_REJ_REPLY_LEN;
  
  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka sending authorisation "
                               "reject reply"));

  pkt = ssh_eap_create_reply(eap, (SshUInt16)(pkt_len - 5), 
                             protocol->impl->id);
  if (!pkt)
    {
      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }
  
  buf[0] = SSH_EAP_AKA_AUTH_REJECT;
  buf[1] = buf[2] = 0;
  if (ssh_buffer_append(pkt, buf, 3) != SSH_BUFFER_OK)
    {
      ssh_buffer_free(pkt);

      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }
  
  ssh_eap_protocol_send_response(protocol, eap, pkt);
}

static void
ssh_eap_aka_send_challenge_reply(SshEapProtocol protocol,
                                 SshEap eap)
{
  SshEapAkaState state        = NULL;
  SshBuffer      pkt          = NULL;
  SshUInt8       buf[3]       = "";
  SshUInt8       rval         = 0;
  SshUInt16      pkt_len      = 0; 
  SshUInt16      res_byte_len = 0;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);

  state = ssh_eap_protocol_get_state(protocol);

  SSH_ASSERT(state != NULL);
             
  res_byte_len = (state->aka_id.res_len / 8) + 
    ((state->aka_id.res_len % 8) ? 1 : 0);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka sending challenge reply"));
  
  /* The SSH_EAP_AKA_CHALLENGE_REPLY_LEN is the maximum length of 
     challenge reply. If the RES is not 16 bytes, well need to reduce 
     the packet length. */
  pkt_len = SSH_EAP_AKA_CHALLENGE_REPLY_LEN - (16 - res_byte_len);

  pkt = ssh_eap_create_reply(eap, (SshUInt16)(pkt_len - 5), 
                             protocol->impl->id);
  if (!pkt)
    {
      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }
  
  buf[0] = SSH_EAP_AKA_CHALLENGE;
  buf[1] = buf[2] = 0;
  if (ssh_buffer_append(pkt, buf, 3) != SSH_BUFFER_OK)
    {
      ssh_buffer_free(pkt);

      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }
  
  if (!ssh_eap_packet_append_res_attr(pkt, state->aka_id.res, 
                                      state->aka_id.res_len))
    {
      ssh_buffer_free(pkt);

      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }

  if (!(ssh_eap_packet_append_empty_mac_attr(pkt)))
    {
      ssh_buffer_free(pkt);

      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    } 

  if (protocol->impl->id == SSH_EAP_TYPE_AKA)
    {
      rval = ssh_eap_packet_calculate_hmac_sha(pkt, state->aut.K_aut, 
                                               NULL, 0, FALSE);
    }
#ifdef SSHDIST_EAP_AKA_DASH
  else if (protocol->impl->id == SSH_EAP_TYPE_AKA_DASH)
    {
      rval = ssh_eap_packet_calculate_hmac_sha256(pkt, state->aut.K_aut_dash,
                                                  NULL, 0, FALSE);
    }
#endif /* SSHDIST_EAP_AKA_DASH */
  if (!rval)
    {
      ssh_buffer_free(pkt);
      ssh_eap_fatal(eap, protocol, "eap aka could not calculate mac for" 
                    " challenge response");
      return;
    }
  
  ssh_eap_protocol_send_response(protocol, eap, pkt);
}

static void
ssh_eap_aka_send_notification_reply(SshEapProtocol protocol,
                                    SshEap eap, SshUInt8 include_mac)
{
  SshEapAkaState state     = NULL;
  SshBuffer      pkt       = NULL;
  SshUInt8       buf[3]    = "";
  SshUInt16      pkt_len   = SSH_EAP_AKA_NOTIF_REPLY_LEN; 

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka sending notification reply"));
  
  state = ssh_eap_protocol_get_state(protocol);
    
  if (include_mac)
    pkt_len += 20;

  pkt = ssh_eap_create_reply(eap, (SshUInt16)(pkt_len - 5), 
                             protocol->impl->id);
  if (!pkt)
    {
      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }
  
  buf[0] = SSH_EAP_NOTIFICATION;
  buf[1] = buf[2] = 0;

  if (ssh_buffer_append(pkt, buf, 3) != SSH_BUFFER_OK)
    {
      ssh_buffer_free(pkt);

      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }
  
  if (include_mac)
    {
      SshUInt8 rval = 0;

      if (!(ssh_eap_packet_append_empty_mac_attr(pkt)))
        {
          ssh_buffer_free(pkt);

          ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
          return;
        }
      
      if (protocol->impl->id == SSH_EAP_TYPE_AKA)
        {
	  rval = ssh_eap_packet_calculate_hmac_sha(pkt, state->aut.K_aut, 
                                                   NULL, 0, FALSE);
	}
#ifdef SSHDIST_EAP_AKA_DASH
      else if (protocol->impl->id == SSH_EAP_TYPE_AKA_DASH)
        {
	  rval = ssh_eap_packet_calculate_hmac_sha256(pkt, 
		                                      state->aut.K_aut_dash,
                                                      NULL, 0, FALSE);
	}
#endif /* SSHDIST_EAP_AKA_DASH */
      
      if (!rval)
        {
          ssh_buffer_free(pkt);

          ssh_eap_fatal(eap, protocol, "eap aka could not calculate mac for" 
                        " nofitication response");
          return;
        }
    }

  ssh_eap_protocol_send_response(protocol, eap, pkt);
}

static void
ssh_eap_aka_client_recv_identity(SshEapProtocol protocol, 
                                 SshEap eap, 
                                 SshBuffer buf) 
{
  SshEapAkaState state = NULL;
  SshUInt8       rval  = 0;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(buf != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka processing start message"));

  state = ssh_eap_protocol_get_state(protocol);
  
  if (state->aka_proto_flags & SSH_EAP_AKA_CHALLENGE_RCVD)
    {
      ssh_eap_discard_packet(eap, protocol, buf, "eap aka identity message"
                             " received when we are already entered state"
                             " for processing challenges");
      ssh_eap_aka_client_error(protocol, eap, 
                               SSH_EAP_AKA_ERR_INVALID_STATE);
      return;
    }

  if ((rval = ssh_eap_aka_decode_identity(protocol, buf)) != 0)
    {
      /* We encountered a problem and in certain cases we signal 
	 it back to the AAA server depending on the return value. */
      SSH_DEBUG(SSH_D_FAIL, ("eap aka start message decoding "
                             "failed, reason: %u", rval));
      
      ssh_eap_discard_packet(eap, protocol, buf, "eap aka"
			     " decoding error, authentication terminated");
      ssh_eap_aka_client_error(protocol, eap, rval);
      return;
    }
  
  state->aka_proto_flags |= SSH_EAP_AKA_IDENTITY_RCVD;
  state->response_id      = ssh_eap_packet_get_identifier(buf);
  
  ssh_eap_protocol_request_token(eap, protocol->impl->id,
				 SSH_EAP_TOKEN_USERNAME);
}

static void
ssh_eap_aka_client_recv_challenge(SshEapProtocol protocol, 
				  SshEap eap, 
				  SshBuffer buf) 
{
  SshEapAkaState   state    = NULL;
  SshUInt8         rval     = 0;
  unsigned char    chal[32] = "";

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(buf != NULL);
  
  state = ssh_eap_protocol_get_state(protocol);
  SSH_DEBUG(SSH_D_NICETOKNOW,("eap aka, processing client" 
                              " challenge request message."));

  /* Freeradius 1.1.4 and below seem to be answering with new challenge
     message altough client-error message has been sent to it. This is 
     totally against RFC 4187. */
  if (state->aka_proto_flags & SSH_EAP_AKA_CHALLENGE_RCVD)
    {
      ssh_eap_discard_packet(eap, protocol, buf, "eap aka multiple challenge"
                             " messages received");
      ssh_eap_aka_client_error(protocol, eap, 
                               SSH_EAP_AKA_ERR_INVALID_STATE);
      return;
    }

  state->aka_proto_flags |= SSH_EAP_AKA_CHALLENGE_RCVD;

  /* Probably a retransmission of RAND challenge? Anyway
     discard it silently. Only done when we are actually 
     processing the RAND's. If we receive this message when 
     we are already setup, we'll send an error message... */
  if (state->aka_proto_flags & SSH_EAP_AKA_PROCESSING_RAND)
    {
      ssh_eap_discard_packet(eap, protocol, buf, "eap aka" 
			     " already waiting for PM's response" 
			     " for RAND challenge.");
      return;
    }

  rval = ssh_eap_aka_decode_challenge(protocol, buf, state->aka_id.rand, 
                                      state->aka_id.autn);
  if (rval != SSH_EAP_AKA_DEC_OK)
    {
      ssh_eap_aka_client_error(protocol, eap, rval); 
      ssh_eap_discard_packet(eap, protocol, buf, "eap aka"
			     " decoding error, authentication terminated");
      return;
    }

  if ((state->last_pkt = ssh_buffer_allocate()) == NULL)
    {
      ssh_eap_discard_packet(eap, protocol, buf, "eap aka fatal error,"
                             " memory allocation for packet failed.");
      return;
    }

  if (ssh_buffer_append(state->last_pkt, ssh_buffer_ptr(buf), 
                        ssh_buffer_len(buf)) != SSH_BUFFER_OK)
    {
      ssh_buffer_free(state->last_pkt);
      state->last_pkt = NULL;

      ssh_eap_discard_packet(eap, protocol, buf, "eap aka fatal error,"
                             " memory allocation for packet failed.");
      return;
    }

  state->aka_proto_flags |= SSH_EAP_AKA_PROCESSING_RAND;

  /* If we have got the username from identity round, 
     use it, otherwise first request for username and
     after that send token for challenge. */
  if (state->user) 
    {
      memcpy(chal, state->aka_id.rand, 16);
      memcpy(&chal[16], state->aka_id.autn, 16);
      
      ssh_eap_protocol_request_token_with_args(eap, protocol->impl->id, 
                                               SSH_EAP_TOKEN_AKA_CHALLENGE,
                                               chal, 32);
    }
  else
    {
      ssh_eap_protocol_request_token(eap, protocol->impl->id,
                                     SSH_EAP_TOKEN_USERNAME);
    }
}

#ifdef SSHDIST_EAP_AKA_DASH
static void
ssh_eap_aka_dash_client_recv_challenge(SshEapProtocol protocol, 
                                       SshEap eap, 
                                       SshBuffer buf)
{
  SshEapAkaState   state    = NULL;
  SshUInt8         rval     = 0;
  unsigned char    chal[32] = "";

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(buf != NULL);
  
  state = ssh_eap_protocol_get_state(protocol);
  SSH_DEBUG(SSH_D_NICETOKNOW,("eap aka dash, processing client" 
                              " challenge request message."));

  if ((state->aka_proto_flags & SSH_EAP_AKA_CHALLENGE_RCVD) && 
      !(state->aka_proto_flags & SSH_EAP_AKA_DASH_CHALLENGE_KDF_ALT_SENT))
    {
      ssh_eap_discard_packet(eap, protocol, buf,
                             "eap aka dash multiple challenge"
                             " messages received");
      ssh_eap_aka_client_error(protocol, eap, 
                               SSH_EAP_AKA_ERR_INVALID_STATE);
      return;
    }

  state->aka_proto_flags |= SSH_EAP_AKA_CHALLENGE_RCVD;

  /* Probably a retransmission of RAND challenge? Anyway
     discard it silently. Only done when we are actually 
     processing the RAND's. If we receive this message when 
     we are already setup, we'll send an error message... */
  if (state->aka_proto_flags & SSH_EAP_AKA_PROCESSING_RAND)
    {
      ssh_eap_discard_packet(eap, protocol, buf, "eap aka dash" 
			     " already waiting for PM's response" 
			     " for RAND challenge.");
      return;
    }

  /* Decode the received challenge */
  rval = ssh_eap_aka_dash_decode_challenge(protocol, buf,
                                           state->aka_id.rand,
                                           state->aka_id.autn);

  /* Check the AUTN INCORRECT case */
  if (rval == SSH_EAP_AKA_DASH_ERR_AUTN_INCORRECT)
    {
      /* Send EAP-Response as AUTN incorrect */
      ssh_eap_aka_auth_reject(protocol, eap, buf);
      return;
    }
  
  /* AT_KDF suggested by server is not our preferred one, 
     let him know what is our preferred one */
  if (rval == SSH_EAP_AKA_DASH_ERR_ALT_KDF)
    {
      /* Send EAP-Response as alternative suggested KDF */
      ssh_eap_aka_dash_send_challenge_alt_kdf(protocol, eap, buf);
      return;
    }

  /* Any other error case result into notify the client error and 
     discard packet */
  if (rval != SSH_EAP_AKA_DEC_OK)
    {
      ssh_eap_aka_client_error(protocol, eap, rval);
      ssh_eap_discard_packet(eap, protocol, buf, "eap aka dash"
			     " decoding error, authentication terminated");
      return;
    }

  if ((state->last_pkt = ssh_buffer_allocate()) == NULL)
    {
      ssh_eap_discard_packet(eap, protocol, buf, "eap aka dash fatal error,"
                             " memory allocation for packet failed.");
      return;
    }

  if (ssh_buffer_append(state->last_pkt, ssh_buffer_ptr(buf), 
                        ssh_buffer_len(buf)) != SSH_BUFFER_OK)
    {
      ssh_buffer_free(state->last_pkt);
      state->last_pkt = NULL;

      ssh_eap_discard_packet(eap, protocol, buf, "eap aka dash fatal error,"
                             " memory allocation for packet failed.");
      return;
    }

  state->aka_proto_flags |= SSH_EAP_AKA_PROCESSING_RAND;

  /* if verify_kdfinput is TRUE then, verify the network_name obtained 
     from AT_KDF_INPUT. Otherwise, we use the network_name without
     verification for calculating the CK' and IK' */
  if (state->verify_kdfinput == TRUE)
    {
      if (state->network_name)
        {
          SSH_ASSERT(state->network_name_len ==
                     ssh_buffer_len(state->network_name));

          ssh_eap_protocol_request_token_with_args(eap, protocol->impl->id,
                                  SSH_EAP_TOKEN_AKA_DASH_KDF_INPUT,
                                  ssh_buffer_ptr(state->network_name),
                                  state->network_name_len);
        }
    }
  else
    {
      /* If we have got the username from identity round, 
         use it, otherwise first request for username and
         after that send token for challenge. */
      if (state->user)
        {
          memcpy(chal, state->aka_id.rand, 16);
          memcpy(&chal[16], state->aka_id.autn, 16);
	      
          ssh_eap_protocol_request_token_with_args(eap,
                                      protocol->impl->id,
                        	      SSH_EAP_TOKEN_AKA_CHALLENGE,
                                      chal, 32);
        }
      else
        {
          ssh_eap_protocol_request_token(eap, protocol->impl->id,
                                         SSH_EAP_TOKEN_USERNAME);
        }
    }
}
#endif /* SSHDIST_EAP_AKA_DASH */

static void 
ssh_eap_aka_client_recv_notification(SshEapProtocol protocol,
                                     SshEap eap,
                                     SshBuffer buf)
{
  SshEapAkaState state = NULL;
  SshUInt16      ret   = 0;
  SshUInt8       rval  = 0;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(buf != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("processing eap aka notification"));

  state = ssh_eap_protocol_get_state(protocol);

  if ((rval = ssh_eap_aka_decode_notification(protocol, buf, &ret)) != 
      SSH_EAP_AKA_DEC_OK)
    {
      ssh_eap_aka_client_error(protocol, eap, rval);
      ssh_eap_discard_packet(eap, protocol, buf, "eap aka invalid packet");
      return;
    }

  /* Do we have to verify the MAC? */
  if (!(ret & 0x4000))
    {
      SshUInt8 result = 0;

      if (protocol->impl->id == SSH_EAP_TYPE_AKA)
        {
	  result = ssh_eap_packet_calculate_hmac_sha(buf, state->aut.K_aut, 
                                                     NULL, 0, TRUE);
	}
#ifdef SSHDIST_EAP_AKA_DASH
      else if (protocol->impl->id == SSH_EAP_TYPE_AKA_DASH)
        {
	  result = ssh_eap_packet_calculate_hmac_sha256(buf,
			                                state->aut.K_aut_dash,
                                                        NULL, 0, TRUE);
	}
#endif /* SSHDIST_EAP_AKA_DASH */
      if (!result)
        {
          ssh_eap_aka_client_error(protocol, eap, SSH_EAP_AKA_ERR_INVALID_IE);
          ssh_eap_discard_packet(eap, protocol, buf, "eap aka server sent"
                                 " aka notify with invalid mac");
          return;
        }
    }

  if (ret & 0x8000)
    {
      /* Success message. Discard and send error. Shouldn't be
         getting these since we did not approve protected successes. */
      ssh_eap_aka_client_error(protocol, eap, SSH_EAP_AKA_ERR_GENERAL);
      ssh_eap_discard_packet(eap, protocol, buf, "eap aka server sent"
                             " aka success");
      return;
    }

  if ((ret & 0x4000) && 
      state->aka_proto_flags & SSH_EAP_AKA_CHALLENGE_RCVD)
    {
      ssh_eap_aka_client_error(protocol, eap, SSH_EAP_AKA_ERR_GENERAL);
      ssh_eap_discard_packet(eap, protocol, buf, "eap aka server sent"
                             " aka nofitication with invalid phase bit");
      return;
    }

  if (!(ret & 0x4000) &&
      !(state->aka_proto_flags & SSH_EAP_AKA_CHALLENGE_RCVD))
    {
      ssh_eap_aka_client_error(protocol, eap, SSH_EAP_AKA_ERR_GENERAL);
      ssh_eap_discard_packet(eap, protocol, buf, "eap aka server sent"
                             " aka nofitication with invalid phase bit");
      return;
    }

  ssh_eap_aka_send_notification_reply(protocol, eap, !(ret & 0x4000));
  
  /* Inform the upper layer that something has gone bad here. */
  ssh_eap_protocol_auth_fail(protocol, eap,
                             SSH_EAP_SIGNAL_AUTH_FAIL_NEGOTIATION, NULL);
}

static void
ssh_eap_aka_client_recv_msg(SshEapProtocol protocol,
                            SshEap eap,
                            SshBuffer buf)
{
  SshEapAkaState state   = NULL;
  SshUInt16      msg_len = 0;
  
  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(buf != NULL);

  state = ssh_eap_protocol_get_state(protocol);
  
  if (state == NULL)
    {
      ssh_eap_discard_packet(eap, protocol, buf,
                             "EAP AKA state uninitialized");
      return;
    }

  /* Here we handle only EAP-AKA specific messages. some notifications
     and Identity requests etc... are handled in ssheap_common. */
  if (ssh_buffer_len(buf) < 6)
    {
      ssh_eap_discard_packet(eap, protocol, buf,
                             "packet too short to be eap aka request");
      return;
    }

  msg_len = (ssh_buffer_ptr(buf)[2] << 8 ) | 
    ssh_buffer_ptr(buf)[3];
  
  if (msg_len != ssh_buffer_len(buf)) 
    {
      ssh_eap_discard_packet(eap, protocol, buf, 
			     "EAP AKA msg length invalid");
      return;
    }
  
  switch (ssh_buffer_ptr(buf)[5]) 
    {
    case SSH_EAP_AKA_IDENTITY:
      
      ssh_eap_aka_client_recv_identity(protocol, eap, buf);
      break;
      
    case SSH_EAP_AKA_CHALLENGE:
      
      if (protocol->impl->id == SSH_EAP_TYPE_AKA)
        ssh_eap_aka_client_recv_challenge(protocol, eap, buf);
#ifdef SSHDIST_EAP_AKA_DASH
      else if (protocol->impl->id == SSH_EAP_TYPE_AKA_DASH)
  	ssh_eap_aka_dash_client_recv_challenge(protocol, eap, buf);
#endif /* SSHDIST_EAP_AKA_DASH */
      break;
      
    case SSH_EAP_REAUTHENTICATION:
      /* The AAA server is really misbehaving. We really do
	 not wan't these messages, because we always indicate we
	 do not support fast reauthentication. Discard the message, send
	 error and tear everything down. */
      ssh_eap_discard_packet(eap, protocol, buf, "eap aka reauthentication"
			     " requested by server, authentication"
			     " terminated");
      ssh_eap_aka_client_error(protocol, eap, 
			       SSH_EAP_AKA_ERR_GENERAL);
      break;
      
    case SSH_EAP_NOTIFICATION:
        
      ssh_eap_aka_client_recv_notification(protocol, eap, buf);
      break;

    default:

      ssh_eap_discard_packet(eap, protocol, buf, 
			     "Invalid EAP AKA subtype");
      ssh_eap_aka_client_error(protocol, eap, 
			       SSH_EAP_AKA_ERR_GENERAL);
      break;
    }
}

SshUInt8 
ssh_eap_aka_calculate_keys(SshEapProtocol protocol, SshEap eap, 
                           unsigned char *generated_keys)
{
  SshRandom          fips         = NULL;
  SshEapAkaState     state        = NULL;
  SshHash            hash         = NULL;
  unsigned char      mk[20]       = "";
  unsigned char      *key_buf     = generated_keys;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(generated_keys != NULL);
    
  state = ssh_eap_protocol_get_state(protocol);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka calculating keys"));

  if (ssh_hash_allocate("sha1", &hash) != SSH_CRYPTO_OK)
    return 1;
    
  ssh_hash_reset(hash);

  /* MK generation section. 
     MK = SHA1(Identity, IK, CK) */
  ssh_hash_update(hash, ssh_buffer_ptr(state->user), state->user_len);
  
  ssh_hash_update(hash, state->aka_id.IK, SSH_EAP_AKA_IK_LEN);
  ssh_hash_update(hash, state->aka_id.CK, SSH_EAP_AKA_CK_LEN);
  
  if (ssh_hash_final(hash, mk) != SSH_CRYPTO_OK)
    goto fail_hash;

  /* Generate the MSK, EMSK, K_aut and K_encr keys. */
  if (ssh_random_allocate("ansi-x9.62", &fips) != SSH_CRYPTO_OK)
    goto fail_hash;

  if (ssh_random_add_entropy(fips, mk, 20, 160) != SSH_CRYPTO_OK)
    {
      ssh_random_free(fips);
      goto fail_hash;
    }
  
  if (ssh_random_get_bytes(fips, key_buf, 160) != SSH_CRYPTO_OK)
    {
      ssh_random_free(fips);
      goto fail_hash;
    }

  ssh_random_free(fips);
  ssh_hash_free(hash);

  return 0;
  
 fail_hash:
  ssh_hash_free(hash);
  SSH_DEBUG(SSH_D_FAIL, ("Key generation failed"));
  
  return 1;
}

#ifdef SSHDIST_EAP_AKA_DASH
static SshUInt8 
ssh_eap_aka_dash_derive_ck_ik_dash(SshEapProtocol protocol, SshEap eap)
{
  SshEapAkaState     state = NULL;
  SshMac             mac = NULL;
  SshCryptoStatus    status;
  
  unsigned char      key[SSH_EAP_AKA_CK_LEN + SSH_EAP_AKA_IK_LEN] = "";
  unsigned char      buffer[SSH_MAX_HASH_DIGEST_LENGTH];
  SshUInt8           fc;
  SshUInt8           l0[2];
  SshUInt8           l1[2];

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);

  state = ssh_eap_protocol_get_state(protocol);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Deriving CK' and IK'"));

  /* As per 3GPP TS 33.402 V8.0.0
     (CK', IK') = F(CK, IK, <access network identity>)

     Change Request 33.402 CR 0033 to version 8.1.1 from
     3GPP TSG-SA WG3 Meeting #53 in year 2008 made corrections
     as given below:

     CR doc name:
     33402_CR0033_(Rel-8)_S3-081100 revised S3-081071 PCR 33402 Annex 
     A KDF.doc

     CK' || IK' = HMAC-SHA-256(Key, S)
     where key and S are as follows:
     
     Key = CK || IK
     S = FC || P0 || L0 || P1 || L1 || ... || Pn || Ln
     
     FC = 0x20
     P0 = access network identity (3GPP TS 24.302)
     L0 = length of access network identity (2 octets, big endian)
     P1 = SQN xor AK (if AK is not used, AK is treated as 000..0)
     L1 = 0x00 0x06 */

  /* Prepare key = CK || IK */
  memcpy(key, state->aka_id.CK, SSH_EAP_AKA_CK_LEN);
  memcpy(key + SSH_EAP_AKA_CK_LEN, state->aka_id.IK, SSH_EAP_AKA_IK_LEN);

  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("CKIK"), key,
		    SSH_EAP_AKA_CK_LEN + SSH_EAP_AKA_IK_LEN);

  /* Allocate mac. */
  status = ssh_mac_allocate("hmac-sha256", key, sizeof(key), &mac);
  if (status != SSH_CRYPTO_OK)
    return 0;

  ssh_mac_reset(mac);

  /* FC = 0x20 */
  fc = 0x20;
  ssh_mac_update(mac, &fc, 1);
 
  /* P0 = network_name from AT_KDF_INPUT */
  ssh_mac_update(mac, 
		 ssh_buffer_ptr(state->network_name), 
		 state->network_name_len);

  /* L0 = length of acceess network identity (2 octets, big endian) */
  SSH_EAP_PUT_BIGENDIAN16(l0, state->network_name_len);
  ssh_mac_update(mac, l0, sizeof(l0));

  /* P1 = SQN xor AK (if AK is not used, AK is treated as 000..0)
     Note: AUTN = (SQN ^ AK) || AMF || MAC which gives us the 
     required needed 6-octet SQN ^AK for CK',IK' derivation */
  ssh_mac_update(mac, state->aka_id.autn, 6);

  /* L1 = 0x00 0x06 */
  SSH_EAP_PUT_BIGENDIAN16(l1, 6);
  ssh_mac_update(mac, l1, sizeof(l1));

  status = ssh_mac_final(mac, buffer);
  if (status != SSH_CRYPTO_OK)
    {
      ssh_mac_free(mac);
      SSH_DEBUG(SSH_D_FAIL, ("Generation of the mac final failed"));
      return 0;
    }

  
  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("CK'IK'"), buffer,
		    SSH_EAP_AKA_CK_LEN + SSH_EAP_AKA_IK_LEN);
 
  /* Copy the CK' */
  memcpy(state->aka_id.CK_dash, buffer, SSH_EAP_AKA_CK_LEN);
  
  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("CK'"), state->aka_id.CK_dash, 
		    SSH_EAP_AKA_CK_LEN);
  
  /* Copy the IK' */
  memcpy(state->aka_id.IK_dash,
         buffer + SSH_EAP_AKA_CK_LEN, SSH_EAP_AKA_IK_LEN);

  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("IK'"), state->aka_id.IK_dash, 
		    SSH_EAP_AKA_IK_LEN);

  ssh_mac_free(mac);
  return 1;
}

/* Calculated prf' from given prf, and key and data. The
   output will be stored to the `output' buffer, and this
   will generate `output_len' bytes of output. */
static SshCryptoStatus
ssh_eap_aka_dash_prf(const unsigned char *prf,
		     const unsigned char *key,
		     size_t key_len,
		     const unsigned char *data,
		     size_t data_len,
		     unsigned char *output,
		     size_t output_len)
{
  unsigned char buffer[SSH_MAX_HASH_DIGEST_LENGTH];
  SshCryptoStatus status;
  unsigned char ch;
  size_t mac_len;
  SshMac mac;
  
  /* Allocate mac. */
  status = ssh_mac_allocate(ssh_csstr(prf), key, key_len, &mac);
  if (status != SSH_CRYPTO_OK)
    return status;

  /* Get the MAC len. */
  mac_len = ssh_mac_length(ssh_csstr(prf));

 /* PRF'(K,S) = T1 | T2 | T3 | T4 | ...
    where:
    T1 = HMAC-SHA-256 (K, S | 0x01)
    T2 = HMAC-SHA-256 (K, T1 | S | 0x02)
    T3 = HMAC-SHA-256 (K, T2 | S | 0x03)
    T4 = HMAC-SHA-256 (K, T3 | S | 0x04)
    ... */
  
  ch = 1;
  while (1)
    {
      ssh_mac_reset(mac);
      if (ch != 1)
	{
	  ssh_mac_update(mac, buffer, mac_len);
	}
      ssh_mac_update(mac, data, data_len);
      ssh_mac_update(mac, &ch, 1);
      status = ssh_mac_final(mac, buffer);
      if (status != SSH_CRYPTO_OK)
	{
	  ssh_mac_free(mac);
	  return status;
	}
	
      if (output_len < mac_len)
	{
	  memcpy(output, buffer, output_len);
	  break;
	}
      memcpy(output, buffer, mac_len);
      output_len -= mac_len;
      output += mac_len;

      if (ch == 255)
	{
	  ssh_mac_free(mac);
	  return SSH_CRYPTO_DATA_TOO_LONG;
	}
      ch++;
    }
  ssh_mac_free(mac);
  return SSH_CRYPTO_OK;
}

SshUInt8 
ssh_eap_aka_dash_calculate_keys(SshEapProtocol protocol,
		                SshEap eap, 
                                unsigned char *generated_keys)
{
  SshEapAkaState        state = NULL;
  unsigned char         key[SSH_EAP_AKA_CK_LEN + SSH_EAP_AKA_IK_LEN] = "";
  unsigned char         *mk = generated_keys;
  SshBufferStruct       data;
  
  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(generated_keys != NULL);
   
  state = ssh_eap_protocol_get_state(protocol);

  ssh_buffer_init(&data);

  /* We support only the sha256 */
  if (state->use_kdf != SSH_EAP_KDF_SHA256)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Eap aka-dash support only kdf: %d,received %d", 
			      SSH_EAP_KDF_SHA256, state->use_kdf));
      goto fail;
    }

  /* Derive the CK' and IK' using the CK and IK */
  if (!ssh_eap_aka_dash_derive_ck_ik_dash(protocol, eap))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Eap aka-dash: Derivation of ck',ik' failed"));
      goto fail;
    }
  
  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka-dash calculating keys"));

  /* MK generation as follows: 
     MK = PRF'(IK'|CK',"EAP-AKA'"|Identity) */

  memcpy(key, state->aka_id.IK_dash, SSH_EAP_AKA_IK_LEN);
  memcpy(key + SSH_EAP_AKA_IK_LEN, 
         state->aka_id.CK_dash, SSH_EAP_AKA_CK_LEN);
  
  /* Append the string "EAP-AKA'" to the data */
  if (ssh_buffer_append(&data, ssh_ustr("EAP-AKA'"), 8) != SSH_BUFFER_OK)
    {
      goto fail; 
    }
  
  /* Append the Identity to the data */
  if (ssh_buffer_append(&data, 
			ssh_buffer_ptr(state->user),
			state->user_len) != SSH_BUFFER_OK)
    {
      goto fail;
    }
 
  /* Calculate the prf */
  if (ssh_eap_aka_dash_prf("hmac-sha256",
			   key,
			   sizeof(key),
			   ssh_buffer_ptr(&data),
			   8 + state->user_len,
			   mk, 
			   208) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Eap aka-dash, prf failed"));
      goto fail;
    }
  
  ssh_buffer_uninit(&data);
  return 0;
  
 fail:
  SSH_DEBUG(SSH_D_FAIL, ("Key generation failed"));
  ssh_buffer_uninit(&data);
  return 1;
}
#endif /* SSHDIST_EAP_AKA_DASH */

static void 
ssh_eap_aka_auth_reject(SshEapProtocol protocol,
                        SshEap eap,
                        SshBuffer buf)
{
  ssh_eap_aka_send_auth_reject_reply(protocol, eap);

  ssh_eap_protocol_auth_fail(protocol, eap,
                             SSH_EAP_SIGNAL_AUTH_FAIL_REPLY, NULL);
}

static void 
ssh_eap_aka_recv_token_auth_reject(SshEapProtocol protocol,
                                   SshEap eap,
                                   SshBuffer buf)
{
  ssh_eap_aka_auth_reject(protocol, eap, buf);
}

static void
ssh_eap_aka_recv_token_synch_required(SshEapProtocol protocol, 
                                      SshEap eap,
                                      SshBuffer buf)
{
  SshEapToken      token     = NULL;
  SshEapAkaState   state     = NULL;
  SshUInt8        *auts_ptr  = NULL;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(buf != NULL);
  SSH_ASSERT(eap != NULL);
  
  state = ssh_eap_protocol_get_state(protocol);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka received token auts"));

  token = (SshEapToken)ssh_buffer_ptr(buf);
  if (!(state->aka_proto_flags & SSH_EAP_AKA_PROCESSING_RAND))
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap aka, received sync req"
                                                 " token altough not "
                                                 "requested one"));
      return;
    }

  if (token->token.buffer.len != SSH_EAP_AKA_AUTS_LEN)
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap aka, received invalid" 
                                                 " length AUTS token"));
      
      ssh_buffer_free(state->last_pkt);
      state->last_pkt = NULL;
      state->aka_proto_flags &= ~SSH_EAP_AKA_PROCESSING_RAND;
      return;
      
    }

  if (state->aka_proto_flags & SSH_EAP_AKA_SYNCH_REQ_SENT)
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap aka, multiple synch "
                                                 "requests, terminating "
                                                 "authorisation"));
      ssh_buffer_free(state->last_pkt);
      state->last_pkt = NULL;
      ssh_eap_aka_client_error(protocol, eap, SSH_EAP_AKA_ERR_GENERAL);
      return;
    }

  /* Copy the outputs from token. */
  auts_ptr = token->token.buffer.dptr;
  memcpy(state->aka_id.auts, auts_ptr, SSH_EAP_AKA_AUTS_LEN);

  ssh_buffer_free(state->last_pkt);
  state->last_pkt = NULL;

  state->aka_proto_flags &= ~SSH_EAP_AKA_PROCESSING_RAND;
  state->aka_proto_flags &= ~SSH_EAP_AKA_CHALLENGE_RCVD;
  state->aka_proto_flags |=  SSH_EAP_AKA_SYNCH_REQ_SENT;

  ssh_eap_aka_send_synch_fail_reply(protocol, eap);
}

static void
ssh_eap_aka_recv_token_challenge_response(SshEapProtocol protocol, 
                                          SshEap eap,
                                          SshBuffer buf)
{
  SshEapToken      token     = NULL;
  SshEapAkaState   state     = NULL;
  SshUInt8        *chal_ptr  = NULL;
  unsigned char    keys[160] = "";
  SshUInt32        res_byte_len;
  
  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(buf != NULL);
  
  state = ssh_eap_protocol_get_state(protocol);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka received token rand"));

  token = (SshEapToken)ssh_buffer_ptr(buf);
  if (!(state->aka_proto_flags & SSH_EAP_AKA_PROCESSING_RAND))
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap aka, received challenge"
                                                 " token altough not"
                                                 " requested one"));
      return;
    }

  if (token->token.buffer.len > ((2 * SSH_EAP_AKA_IK_LEN) + 17) ||
      token->token.buffer.len < ((2 * SSH_EAP_AKA_IK_LEN) + 5))
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap aka, received invalid" 
                                                 " length token"));
      
      ssh_buffer_free(state->last_pkt);
      state->last_pkt = NULL;
      state->aka_proto_flags &= ~SSH_EAP_AKA_PROCESSING_RAND;
      return;
      
    }

  /* Copy the outputs from token. */
  chal_ptr = token->token.buffer.dptr;
  memcpy(state->aka_id.IK, chal_ptr, SSH_EAP_AKA_IK_LEN);

  chal_ptr += SSH_EAP_AKA_IK_LEN;
  memcpy(state->aka_id.CK, chal_ptr, SSH_EAP_AKA_CK_LEN);

  chal_ptr += SSH_EAP_AKA_CK_LEN;
  state->aka_id.res_len = *chal_ptr & 0xff;
  res_byte_len = (state->aka_id.res_len / 8) + 
    ((state->aka_id.res_len % 8) ? 1 : 0);

  if (state->aka_id.res_len > 128 || state->aka_id.res_len < 32)
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap aka, received invalid" 
                                                 " length challenge token"));
      
      ssh_buffer_free(state->last_pkt);
      state->last_pkt = NULL;
      state->aka_proto_flags &= ~SSH_EAP_AKA_PROCESSING_RAND;
      return;
      
    }

  memset(state->aka_id.res, 0x0, sizeof(state->aka_id.res));
  memcpy(state->aka_id.res, &chal_ptr[1], res_byte_len);

  if (ssh_eap_aka_calculate_keys(protocol, eap, keys))
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap aka, key generation" 
                                                 " failed, dropping token"));
      ssh_buffer_free(state->last_pkt);
      state->last_pkt = NULL;
      
      state->aka_proto_flags &= ~SSH_EAP_AKA_PROCESSING_RAND;
      ssh_eap_aka_client_error(protocol, eap, SSH_EAP_AKA_ERR_GENERAL);
      return;
    }

  if (!ssh_eap_packet_calculate_hmac_sha(state->last_pkt, &keys[16], 
                                         NULL, 0, TRUE))
    {
      
      ssh_eap_discard_token(eap, protocol, buf, ("eap aka message mac "
                                                 "verification" 
                                                 " failed, dropping token"));
      
      ssh_buffer_free(state->last_pkt);
      state->last_pkt = NULL;
      
      state->aka_proto_flags &= ~SSH_EAP_AKA_PROCESSING_RAND;
      ssh_eap_aka_client_error(protocol, eap, SSH_EAP_AKA_ERR_INVALID_IE);
      return;
    }

  /* Copy the keys, everything should be fine. */
  memcpy(state->K_encr, keys, SSH_EAP_AKA_KENCR_LEN);
  memcpy(state->aut.K_aut, &keys[16], SSH_EAP_AKA_KAUT_LEN);
  memcpy(state->msk, &keys[32], SSH_EAP_AKA_MSK_LEN);
  memcpy(state->emsk, &keys[96], SSH_EAP_AKA_EMSK_LEN);

  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("MSK"), state->msk, SSH_EAP_AKA_MSK_LEN);

  ssh_buffer_free(state->last_pkt);
  state->last_pkt = NULL;

  state->aka_proto_flags &= ~SSH_EAP_AKA_PROCESSING_RAND;

  eap->msk = ssh_memdup(state->msk, SSH_EAP_AKA_MSK_LEN);
  eap->msk_len = SSH_EAP_AKA_MSK_LEN;

  ssh_eap_aka_send_challenge_reply(protocol, eap);
  ssh_eap_protocol_auth_ok(protocol, eap, SSH_EAP_SIGNAL_NONE, NULL);
}

#ifdef SSHDIST_EAP_AKA_DASH
static void
ssh_eap_aka_dash_recv_token_challenge_response(SshEapProtocol protocol,
                                               SshEap eap,
                                               SshBuffer buf)
{
  SshEapToken      token     = NULL;
  SshEapAkaState   state     = NULL;
  SshUInt8        *chal_ptr  = NULL;
  SshUInt32        res_byte_len;

  /* 208 bytes = K_encr(128 bits) + K_aut(256 bits) + K_re(256 bits) +
     msk(512 bits) + emsk(512 bits) */
  unsigned char    keys[208] = "";
  
  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(buf != NULL);
  
  state = ssh_eap_protocol_get_state(protocol);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka-dash received token rand"));

  token = (SshEapToken)ssh_buffer_ptr(buf);
  if (!(state->aka_proto_flags & SSH_EAP_AKA_PROCESSING_RAND))
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap aka-dash, received"
                       		      " challenge token altough not"
                                      " requested one"));
      return;
    }

  /* RES can vary from 4 to 16 bytes */
  if (token->token.buffer.len > ((2 * SSH_EAP_AKA_IK_LEN) + 17) ||
      token->token.buffer.len < ((2 * SSH_EAP_AKA_IK_LEN) + 5))
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap aka-dash, received"
			                         " invalid length token"));
      
      ssh_buffer_free(state->last_pkt);
      state->last_pkt = NULL;
      state->aka_proto_flags &= ~SSH_EAP_AKA_PROCESSING_RAND;
      return;
    }

  /* Copy the outputs from token. */
  chal_ptr = token->token.buffer.dptr;
  memcpy(state->aka_id.IK, chal_ptr, SSH_EAP_AKA_IK_LEN);

  chal_ptr += SSH_EAP_AKA_IK_LEN;
  memcpy(state->aka_id.CK, chal_ptr, SSH_EAP_AKA_CK_LEN);

  chal_ptr += SSH_EAP_AKA_CK_LEN;
  state->aka_id.res_len = *chal_ptr & 0xff;
  res_byte_len = (state->aka_id.res_len / 8) + 
    ((state->aka_id.res_len % 8) ? 1 : 0);

  if (state->aka_id.res_len > 128 || state->aka_id.res_len < 32)
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap aka-dash, received"
               			      " invalid length challenge token"));
      
      ssh_buffer_free(state->last_pkt);
      state->last_pkt = NULL;
      state->aka_proto_flags &= ~SSH_EAP_AKA_PROCESSING_RAND;
      return;
    }

  /* chal_ptr[1], this byte is used for storing the res_len */
  memset(state->aka_id.res, 0x0, sizeof(state->aka_id.res));
  memcpy(state->aka_id.res, &chal_ptr[1], res_byte_len);

  /* Calculate the keys for eap aka-dash */
  if (ssh_eap_aka_dash_calculate_keys(protocol, eap, keys))
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap aka-dash, key generation"
                                                 " failed, dropping token"));
      ssh_buffer_free(state->last_pkt);
      state->last_pkt = NULL;
      
      state->aka_proto_flags &= ~SSH_EAP_AKA_PROCESSING_RAND;
      ssh_eap_aka_client_error(protocol, eap, SSH_EAP_AKA_ERR_GENERAL);
      return;
    }

  /* Keys[16] is pointing to the K_aut_dash which is used in the mac
     verification */
  if (!ssh_eap_packet_calculate_hmac_sha256(state->last_pkt, &keys[16], 
                                            NULL, 0, TRUE))
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap aka-dash message mac "
                                                 "verification failed,"
						 "dropping token"));
      
      ssh_buffer_free(state->last_pkt);
      state->last_pkt = NULL;
      
      state->aka_proto_flags &= ~SSH_EAP_AKA_PROCESSING_RAND;
      ssh_eap_aka_client_error(protocol, eap, SSH_EAP_AKA_ERR_INVALID_IE);
      return;
    }

  /* Copy the keys. */
  /* On Full authentication, Order of the keys will be as follows: 
     K_encr = MK[0..127]
     K_aut  = MK[128..383]
     K_re   = MK[384..639]
     MSK    = MK[640..1151]
     EMSK   = MK[1152..1663]
  */
  memcpy(state->K_encr, keys, SSH_EAP_AKA_KENCR_LEN);
  memcpy(state->aut.K_aut_dash, &keys[16], SSH_EAP_AKA_DASH_KAUT_LEN);
  memcpy(state->msk, &keys[80], SSH_EAP_AKA_MSK_LEN);
  memcpy(state->emsk, &keys[144], SSH_EAP_AKA_EMSK_LEN);

  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("K_encr"), state->K_encr,
		                 SSH_EAP_AKA_KENCR_LEN);
  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("K_aut"), state->aut.K_aut_dash,
		                 SSH_EAP_AKA_DASH_KAUT_LEN);
  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("K_re"), keys + (SSH_EAP_AKA_KENCR_LEN + 
			         SSH_EAP_AKA_DASH_KAUT_LEN),
		                 SSH_EAP_AKA_DASH_KAUT_LEN);
  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("MSK"), state->msk, SSH_EAP_AKA_MSK_LEN);
  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("EMSK"), state->emsk, SSH_EAP_AKA_EMSK_LEN);

  ssh_buffer_free(state->last_pkt);
  state->last_pkt = NULL;

  state->aka_proto_flags &= ~SSH_EAP_AKA_PROCESSING_RAND;

  eap->msk = ssh_memdup(state->msk, SSH_EAP_AKA_MSK_LEN);
  eap->msk_len = SSH_EAP_AKA_MSK_LEN;

  ssh_eap_aka_send_challenge_reply(protocol, eap);
  ssh_eap_protocol_auth_ok(protocol, eap, SSH_EAP_SIGNAL_NONE, NULL);
}

static void
ssh_eap_aka_dash_recv_token_kdf_input(SshEapProtocol protocol, 
                                      SshEap eap,
                                      SshBuffer buf)
{
  SshEapToken    token   = NULL;
  SshEapAkaState state   = NULL;
  unsigned char    chal[32] = "";
  Boolean result;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);

  state = ssh_eap_protocol_get_state(protocol);
  
  token = (SshEapToken)ssh_buffer_ptr(buf);

  if (!(state->aka_proto_flags & SSH_EAP_AKA_PROCESSING_RAND))
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap aka dash, received"
                                                 "sync req token altough not"
						 "requested one"));
      return;
    }

  result = ssh_eap_get_token_kdf_input(token);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Verification of the network name %s",
                               result == TRUE ? "succeed" : "failed"));

  /* As per the draft of aka-dash, result of verifying network name
     result's into FAIL case, then peer SHOULD warns the user or display the
     message of the same and peer can continue the authentication using the
     network name obtained from the AT_KDF_INPUT or fails the authentication.
     Warning display action is already taken care in the PM. However,
     we have chosen to continue the authentication. If we wish to decide the
     the authentication process to terminate then, authentication is failed as
     AUTN incorrect. Send EAP-Response as AUTN incorrect using 
     ssh_eap_aka_auth_reject(). */

  /* If we have got the username from identity round, 
     use it, otherwise first request for username and
     after that send token for challenge. */
  if (state->user)
    {
      memcpy(chal, state->aka_id.rand, 16);
      memcpy(&chal[16], state->aka_id.autn, 16);
      
      ssh_eap_protocol_request_token_with_args(eap,
                                               protocol->impl->id,
                                               SSH_EAP_TOKEN_AKA_CHALLENGE,
                                               chal, 32);
    }
  else
    {
      ssh_eap_protocol_request_token(eap, protocol->impl->id,
                                     SSH_EAP_TOKEN_USERNAME);
    }
}
#endif /* SSHDIST_EAP_AKA_DASH */

static void
ssh_eap_aka_recv_token_username(SshEapProtocol protocol, 
                                SshEap eap,
                                SshBuffer buf)
{
  SshEapToken    token   = NULL;
  SshEapAkaState state   = NULL;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(buf != NULL);
  SSH_ASSERT(eap != NULL);

  state = ssh_eap_protocol_get_state(protocol);
  
  token = (SshEapToken)ssh_buffer_ptr(buf);

  /* Wipe out the old stuff if required. */
  if (state->user) 
    {
      ssh_buffer_free(state->user);
      state->user = NULL;
    }

  if (!token->token.buffer.dptr || token->token.buffer.len <= 0)
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap aka did not receive"
                                                 " valid username"));    
      ssh_eap_protocol_auth_fail(protocol, eap,
				 SSH_EAP_SIGNAL_AUTH_FAIL_NEGOTIATION,
				 NULL);
      return;
    }
  
  state->user = ssh_buffer_allocate();
  if (!state->user)
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap aka buffer"
                                                 " allocation failed"));    
      return;
    }
  
  if (ssh_buffer_append(state->user, token->token.buffer.dptr, 
                        token->token.buffer.len) != SSH_BUFFER_OK)
    {
      ssh_buffer_free(state->user);
      state->user = NULL;

      ssh_eap_discard_token(eap, protocol, buf, ("eap aka buffer"
                                                 " allocation failed"));    
      return;
    }

  state->user_len = (SshUInt8)token->token.buffer.len;

  /* If we have entered already for processing rand, the server
     obviously skipped the identity round and therefore we had
     to first ask for username and after that only we can 
     proceed with processing the rand (so request 
     token AKA_CHALLENGE). */
  if (state->aka_proto_flags & SSH_EAP_AKA_PROCESSING_RAND)
    {
      unsigned char chal[32] = "";

      memcpy(chal, state->aka_id.rand, 16);
      memcpy(&chal[16], state->aka_id.autn, 16);
      
      ssh_eap_protocol_request_token_with_args(eap, protocol->impl->id, 
                                               SSH_EAP_TOKEN_AKA_CHALLENGE,
                                               chal, 32);
    }
  else
    {
      ssh_eap_aka_send_identity_reply(protocol, eap);
    }
}

static void 
ssh_eap_aka_recv_token(SshEapProtocol protocol,
		       SshEap eap, SshBuffer buf)
{
  SshUInt8 token_type = 0;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);
  
  token_type = ssh_eap_get_token_type_from_buf(buf);

  switch (token_type)
    {
    case SSH_EAP_TOKEN_USERNAME:
      SSH_ASSERT(buf != NULL);
      ssh_eap_aka_recv_token_username(protocol, eap, buf);      
      break;

    case SSH_EAP_TOKEN_AKA_CHALLENGE:
      SSH_ASSERT(buf != NULL);
      if (protocol->impl->id == SSH_EAP_TYPE_AKA)
        ssh_eap_aka_recv_token_challenge_response(protocol, eap, buf);
#ifdef SSHDIST_EAP_AKA_DASH
      else if (protocol->impl->id == SSH_EAP_TYPE_AKA_DASH)
        ssh_eap_aka_dash_recv_token_challenge_response(protocol, eap, buf);
#endif /* SSHDIST_EAP_AKA_DASH */
      break;

    case SSH_EAP_TOKEN_AKA_SYNCH_REQ:
      SSH_ASSERT(buf != NULL);
      ssh_eap_aka_recv_token_synch_required(protocol, eap, buf);
      break;

    case SSH_EAP_TOKEN_AKA_AUTH_REJECT:
      ssh_eap_aka_recv_token_auth_reject(protocol, eap, buf);
      break;
#ifdef SSHDIST_EAP_AKA_DASH
    case SSH_EAP_TOKEN_AKA_DASH_KDF_INPUT:
      SSH_ASSERT(buf != NULL);
      ssh_eap_aka_dash_recv_token_kdf_input(protocol, eap, buf);
      break;
#endif /* SSHDIST_EAP_AKA_DASH */
    default:

      ssh_eap_discard_token(eap, protocol, buf, 
                            ("unexpected token type"));    
      return;
    }
}
#endif /* SSHDIST_EAP_AKA */

void
ssh_eap_aka_recv_params(SshEapProtocol protocol,
                        SshEap eap,
                        SshBuffer buf)
{
#ifdef SSHDIST_EAP_AKA
  SshEapAkaState aka;
  SshEapAkaParams params;
  
  aka = ssh_eap_protocol_get_state(protocol);

  params = (SshEapAkaParams)ssh_buffer_ptr(buf);

  if (ssh_buffer_len(buf) != sizeof(*params))
    {
      SSH_DEBUG(SSH_D_FAIL,("Received params struct of incorrect size"));
      return;
    }

  aka->transform = params->transform;
  SSH_ASSERT((aka->transform & SSH_EAP_TRANSFORM_PRF_HMAC_SHA1) ||
             (aka->transform & SSH_EAP_TRANSFORM_PRF_HMAC_SHA256));

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Set transform for AKA to %x",
                              aka->transform));

#ifdef SSHDIST_EAP_AKA_DASH
  aka->verify_kdfinput = params->verify_kdfinput;
  SSH_DEBUG(SSH_D_NICETOKNOW, ("verify_kdfinput is set to %s",
            aka->verify_kdfinput == TRUE ? "TRUE" : "FALSE" ));
#endif /* SSHDIST_EAP_AKA_DASH */
#endif /* SSHDIST_EAP_AKA */
}

void* ssh_eap_aka_create(SshEapProtocol protocol, 
                         SshEap eap, SshUInt8 type)
{
#ifdef SSHDIST_EAP_AKA
  SshEapAkaState state;
  
  state = ssh_malloc(sizeof(*state));
  if (state == NULL)
    return NULL;

  memset(state, 0, sizeof(SshEapAkaStateStruct));

  SSH_DEBUG(SSH_D_NICETOKNOW, ("created eap aka auth state"));

  return state;
#else /* SSHDIST_EAP_AKA */
  return NULL;
#endif /* SSHDIST_EAP_AKA */
}

void
ssh_eap_aka_destroy(SshEapProtocol protocol, 
                    SshUInt8 type, void *state)
{
#ifdef SSHDIST_EAP_AKA
  SshEapAkaState statex;

  statex = ssh_eap_protocol_get_state(protocol);
  
  if (statex)
    {
      if (statex->user)
        ssh_buffer_free(statex->user);
      
      if (statex->last_pkt)
        ssh_buffer_free(statex->last_pkt);
      
#ifdef SSHDIST_EAP_AKA_DASH
      if (statex->network_name)
        ssh_buffer_free(statex->network_name);
#endif /* SSHDIST_EAP_AKA_DASH */
      ssh_free(protocol->state);
    }
  
  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka state destroyed"));
#endif /* SSHDIST_EAP_AKA */
}

SshEapOpStatus
ssh_eap_aka_signal(SshEapProtocolSignalEnum sig,
                   SshEap eap,
                   SshEapProtocol protocol,
                   SshBuffer buf)
{
#ifdef SSHDIST_EAP_AKA
  if (ssh_eap_isauthenticator(eap) == TRUE) 
    {
      switch (sig)
        {
        case SSH_EAP_PROTOCOL_RESET:
          SSH_ASSERT(buf == NULL);
          break;

        case SSH_EAP_PROTOCOL_BEGIN:
          SSH_ASSERT(buf == NULL);
          break;

        case SSH_EAP_PROTOCOL_RECV_MSG:
          SSH_ASSERT(buf != NULL);
          break;

        case SSH_EAP_PROTOCOL_RECV_TOKEN:
          SSH_ASSERT(buf != NULL);
          break;

	case SSH_EAP_PROTOCOL_RECV_PARAMS:
          SSH_ASSERT(buf != NULL);
          SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka receive params"));
	  ssh_eap_aka_recv_params(protocol, eap, buf);
          break;

        default:
          SSH_NOTREACHED;
        }
    }
  else
    {
      switch (sig)
        {
        case SSH_EAP_PROTOCOL_RESET:
          SSH_ASSERT(buf == NULL);
          SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka signal protocol reset"));
          break;
	  
        case SSH_EAP_PROTOCOL_BEGIN:
          SSH_ASSERT(buf == NULL);
          SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka signal protocol begin"));
          break;

        case SSH_EAP_PROTOCOL_RECV_MSG:
          SSH_ASSERT(buf != NULL);
          ssh_eap_aka_client_recv_msg(protocol, eap, buf);
          break;

        case SSH_EAP_PROTOCOL_RECV_TOKEN:
	  ssh_eap_aka_recv_token(protocol, eap, buf);
          break;

	case SSH_EAP_PROTOCOL_RECV_PARAMS:
          SSH_ASSERT(buf != NULL);
          SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka receive params"));
	  ssh_eap_aka_recv_params(protocol, eap, buf);
          break;
  
        default:
          SSH_NOTREACHED;
        }
    }
#endif /* SSHDIST_EAP_AKA */
  return SSH_EAP_OPSTATUS_SUCCESS;
}

SshEapOpStatus
ssh_eap_aka_key(SshEapProtocol protocol, 
                SshEap eap, SshUInt8 type)
{
  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(eap->is_authenticator == TRUE);

  if (eap->mppe_send_keylen < 32 || eap->mppe_recv_keylen < 32)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Keys too short %d %d", 
                             eap->mppe_send_keylen, 
                             eap->mppe_recv_keylen));
      return SSH_EAP_OPSTATUS_FAILURE;
    }
  
  if ((eap->msk = ssh_malloc(64)) == NULL)
    return SSH_EAP_OPSTATUS_FAILURE;

  eap->msk_len = 64;
  
  memcpy(eap->msk, eap->mppe_recv_key, 32);
  memcpy(eap->msk + 32, eap->mppe_send_key, 32);
  
  SSH_DEBUG_HEXDUMP(SSH_D_MIDOK, ("64 byte EAP-AKA MSK"),
                    eap->msk, eap->msk_len);
 
  return SSH_EAP_OPSTATUS_SUCCESS;
}
