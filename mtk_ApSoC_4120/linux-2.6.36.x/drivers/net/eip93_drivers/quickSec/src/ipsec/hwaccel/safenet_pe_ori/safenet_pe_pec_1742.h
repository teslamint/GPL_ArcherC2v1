/* safenet_pe_pec_1742.h
 *
 * Safenet Look-Aside Accelerator Packet Engine Interface implementation
 * for 1742 chip.
 */

/*****************************************************************************
 *                                                                            *
 *            Copyright (c) 2009 SafeNet Inc. All Rights Reserved.            *
 *                                                                            *
 * This confidential and proprietary software may be used only as authorized  *
 * by a licensing agreement from SafeNet.                                     *
 *                                                                            *
 * The entire notice above must be reproduced on all authorized copies that   *
 * may only be made to the extent permitted by a licensing agreement from     *
 * SafeNet.                                                                   *
 *                                                                            *
 * For more information or support, please go to our online support system at *
 * https://oemsupport.safenet-inc.com or e-mail to oemsupport@safenet-inc.com *
 *                                                                            *
 *****************************************************************************/

#ifndef SAFENET_PE_PEC_1742_H
#define SAFENET_PE_PEC_1742_H

#include "sshincludes.h"
#include "safenet_la_params.h"
#include "safenet_pe_utils.h"

#include "basic_defs.h" 
#include "api_dmabuf.h" /* DMA buf API we use  */
#include "api_pec.h" /* PEC API we use */

#define SAFENET_PEC_PAD_IPSEC 0x000
#define SAFENET_PEC_LOAD_HASH_STATE 0x00

/******** Debug stuff ***********/
#undef SSH_DEBUG_MODULE
#define SSH_DEBUG_MODULE "SshSafenet1x41"

/*  SA revision 0 */
typedef struct SafeNetPecSARec
{
  /* Command 0 */
  uint32_t Command0;
  /* Command 1 */
  uint32_t Command1;
  /* Reserved words for future extensions */
  uint32_t reserved1;
  uint32_t reserved2;
 
  uint32_t Key[8];
  uint8_t InnerDigest[20];
  uint8_t OuterDigest[20];
  uint32_t SPI;
  uint32_t SequenceNum;
  uint32_t SeqNumMask0;
  uint32_t SeqNumMask1;
  uint32_t Nonce;
  uint32_t StatePtr;
  uint32_t ARC4_ij;
  uint32_t ARC4StatePtr;
  uint32_t SAManagement0;
  uint32_t SAManagement1; 
} SafenetPEC_SA_t;

static inline void
SafenetPEC_SA_SetCommand0(
			  uint32_t * ResultWord_p,
			  const uint8_t OpCode,
			  const uint8_t Dir,
			  const uint8_t OpGroup,
			  const uint8_t Pad,
			  const uint8_t Cipher,
			  const uint8_t Hash,
			  const uint8_t SP,
			  const uint8_t EP,
			  const uint8_t HP,
			  const uint8_t DigLen,        
			  const uint8_t LdIV,
			  const uint8_t LdHS,
			  const uint8_t SvIV,
			  const uint8_t SvHS,
			  const uint8_t G,
			  const uint8_t S)
{
  uint32_t word = 0;
  word |=  (OpCode    & (BIT_3-1));
  word |= ((Dir       & (BIT_1-1)) << 3);
  word |= ((OpGroup   & (BIT_2-1)) << 4);
  word |= ((Pad       & (BIT_2-1)) << 6);
  word |= ((Cipher    & (BIT_4-1)) << 8);
  word |= ((Hash      & (BIT_4-1)) << 12);
  word |= ((SP        & (BIT_1-1)) << 17);
  word |= ((EP        & (BIT_1-1)) << 18);
  word |= ((HP        & (BIT_1-1)) << 19);
  word |= ((DigLen    & (BIT_4-1)) << 20);
  word |= ((LdIV      & (BIT_2-1)) << 24);
  word |= ((LdHS      & (BIT_2-1)) << 26);
  word |= ((SvIV      & (BIT_1-1)) << 28);
  word |= ((SvHS      & (BIT_1-1)) << 29);
  word |= ((G         & (BIT_1-1)) << 30);
  word |= ((S         & (BIT_1-1)) << 31);
  *ResultWord_p = word;
}

static inline void
SafenetPEC_SA_SetCommand1(
			  uint32_t * ResultWord_p,
			  const uint8_t CpHdr,
			  const uint8_t CpPay,
			  const uint8_t CpPad,
			  const uint8_t IPversion,
			  const uint8_t MutBit,
			  const uint8_t SNMask,
			  const uint8_t ESN,
			  const uint8_t CMode,
			  const uint8_t FBMode,
			  const uint8_t HMAC_MC,        
			  const uint8_t BOffset,
			  const uint8_t SARev,
			  const uint8_t HCOffset,
			  const uint8_t KeyLen,
			  const uint8_t ARC4SF,
			  const uint8_t SvARC4,
			  const uint8_t CModeEx)
{
  uint32_t word = 0;
  word |= ((CpHdr         & (BIT_1-1)) << 1);
  word |= ((CpPay         & (BIT_1-1)) << 2);
  word |= ((CpPad         & (BIT_1-1)) << 3);
  word |= ((IPversion     & (BIT_1-1)) << 4);
  word |= ((MutBit        & (BIT_1-1)) << 5);
  word |= ((SNMask        & (BIT_1-1)) << 6);
  word |= ((ESN           & (BIT_1-1)) << 7);
  word |= ((CMode         & (BIT_2-1)) << 8);
  word |= ((FBMode        & (BIT_2-1)) << 10);
  word |= ((HMAC_MC       & (BIT_1-1)) << 12);
  word |= ((BOffset       & (BIT_1-1)) << 13);
  word |= ((SARev         & (BIT_1-1)) << 14);    
  word |= ((HCOffset      & (BIT_8-1)) << 16);
  word |= ((KeyLen        & (BIT_5-1)) << 24);
  word |= ((ARC4SF        & (BIT_1-1)) << 29);
  word |= ((SvARC4        & (BIT_1-1)) << 30);
  word |= ((CModeEx         & (BIT_1-1)) << 31);
  *ResultWord_p = word;
}        

static inline void
SafenetPEC_SA_GetCommand0(
			  const uint32_t InputWord,
			  uint8_t * OpCode,
			  uint8_t * Dir,
			  uint8_t * OpGroup,
			  uint8_t * Pad,
			  uint8_t * Cipher,
			  uint8_t * Hash,
			  uint8_t * SP,
			  uint8_t * EP,
			  uint8_t * HP,
			  uint8_t * DigLen,        
			  uint8_t * LdIV,
			  uint8_t * LdHS,
			  uint8_t * SvIV,
			  uint8_t * SvHS,
			  uint8_t * G,
			  uint8_t * S)
{
  *OpCode =   (InputWord)       &  (BIT_3-1);
  *Dir =      (InputWord >> 3)  &  (BIT_1-1);
  *OpGroup =  (InputWord >> 4)  &  (BIT_2-1);
  *Pad =      (InputWord >> 6)  &  (BIT_3-1);
    
  *Cipher =   (InputWord >> 8)  &  (BIT_4-1);
  *Hash =     (InputWord >> 12) &  (BIT_4-1);
  *SP =       (InputWord >> 17) &  (BIT_1-1);
  *EP =       (InputWord >> 18) &  (BIT_1-1);
    
  *HP =       (InputWord >> 19) &  (BIT_1-1);
  *DigLen =   (InputWord >> 20) &  (BIT_4-1);
  *LdIV =     (InputWord >> 24) &  (BIT_2-1);
  *LdHS =     (InputWord >> 26) &  (BIT_2-1);
    
  *SvIV =     (InputWord >> 28) &  (BIT_1-1);
  *SvHS =     (InputWord >> 29) &  (BIT_1-1);
  *G =        (InputWord >> 30) &  (BIT_1-1);
  *S =        (InputWord >> 31) &  (BIT_1-1);
}

static inline void
SafenetPEC_SA_GetCommand1(
			  const uint32_t InputWord,
			  uint8_t * CpHdr,
			  uint8_t * CpPay,
			  uint8_t * CpPad,
			  uint8_t * IPversion,
			  uint8_t * MutBit,
			  uint8_t * SNMask,
			  uint8_t * ESN,
			  uint8_t * CMode,
			  uint8_t * FBMode,
			  uint8_t * HMAC_MC,        
			  uint8_t * BOffset,
			  uint8_t * SARev,
			  uint8_t * HCOffset,
			  uint8_t * KeyLen,
			  uint8_t * ARC4SF,
			  uint8_t * SvARC4,
			  uint8_t * CModeEx)
{
  *CpHdr =    ((InputWord) >> 1)&  (BIT_1-1);
  *CpPay =    (InputWord >> 2)  &  (BIT_1-1);
  *CpPad =    (InputWord >> 3)  &  (BIT_1-1);
  *IPversion =(InputWord >> 4)  &  (BIT_1-1);
  *MutBit =   (InputWord >> 5)  &  (BIT_1-1);
  *SNMask =   (InputWord >> 6)  &  (BIT_1-1);
  *ESN =      (InputWord >> 7)  &  (BIT_1-1);
  *CMode =    (InputWord >> 8)  &  (BIT_2-1);
  *FBMode =   (InputWord >> 10) &  (BIT_2-1);
  *HMAC_MC =  (InputWord >> 12) &  (BIT_1-1);
  *BOffset =  (InputWord >> 13) &  (BIT_1-1);
  *SARev =    (InputWord >> 14) &  (BIT_1-1);
  *HCOffset = (InputWord >> 28) &  (BIT_8-1);
  *KeyLen =   (InputWord >> 29) &  (BIT_5-1);
  *ARC4SF =   (InputWord >> 30) &  (BIT_1-1);
  *SvARC4 =   (InputWord >> 31) &  (BIT_1-1);
  *CModeEx =    (InputWord >> 31) &  (BIT_1-1);
}

/*  State record revision 0 */
typedef struct SafenetPEC_StateRecordRec
{
  /* State record rev 1 */
  uint32_t SaveIV[4];
  uint32_t SaveHashByteCtr;
  uint8_t SaveDigest[20];
} SafenetPEC_StateRecord_t;

/*  Packet Descriptor control words handling */
static inline void
SafenetPEC_PacketDescriptor_SetWord0(
				     uint32_t * ResultWord_p,
				     const uint8_t PadControl,
				     const uint8_t NextHeaderValue,
				     const bool fInitARC4,
				     const bool fHashFinal)
{
  uint32_t word = 0;
  word |= PadControl << 24;
  word |= NextHeaderValue << 8;
  word |= (fHashFinal ? 1 : 0) << 4;
  word |= (fInitARC4 ? 1 : 0) << 3;
  *ResultWord_p = word;
}

static inline void
SafenetPEC_PacketDescriptor_GetWord0(
				     const uint32_t InputWord,
				     uint8_t * PadStatus,
				     uint8_t * NextHeader_PadValue,
				     uint8_t * Status)
{        
  *PadStatus = (InputWord >> 24) &  (BIT_8-1);
  *Status = (InputWord >> 16) &  (BIT_8-1);   
  *NextHeader_PadValue = (InputWord >> 8) &  (BIT_8-1);
}    

/*  Opcodes for opgroups */
typedef enum
  {
    PEC_OPCODE_OPGROUP_BASIC_OP = 0x0,
    PEC_OPCODE_OPGROUP_PROTOCOL_OP = 0x1,
    PEC_OPCODE_OPGROUP_EXT_PROTOCOL_OP = 0x2,
    PEC_OPCODE_OPGROUP_RESERVED = 0x3

  } PEC_OPCODE_OPGROUP;

/* Opcodes for SA direction. */
typedef enum
  { 
    PEC_OPCODE_AH_OUTBOUND = 0x01,
    PEC_OPCODE_AH_INBOUND = 0x01,
    PEC_OPCODE_ESP_OUTBOUND = 0x00,
    PEC_OPCODE_ESP_INBOUND = 0x00
  } Opcodes;

/* Opcodes for cipher algo */
typedef enum
  {
    PEC_OPCODE_CRYPT_DES = 0x0,
    PEC_OPCODE_CRYPT_3DES = 0x1,
    PEC_OPCODE_CRYPT_ARC4 = 0x2,
    PEC_OPCODE_CRYPT_AES = 0x3,
    PEC_OPCODE_CRYPT_NULL = 0xf,
  } CipherAlgo;

/* Opcodes for Hash algorithm */
typedef enum 
  { 
    PEC_OPCODE_HASH_MD5 = 0x0,
    PEC_OPCODE_HASH_SHA_1 = 0x1,
    PEC_OPCODE_HASH_SHA_224 = 0x2,
    PEC_OPCODE_HASH_SHA_256 = 0x3,
    PEC_OPCODE_HASH_SHA_384 = 0x4,
    PEC_OPCODE_HASH_SHA_512 = 0x5,
    PEC_OPCODE_HASH_NULL = 0xf
  } HashAlgo;


#ifdef SAFENET_DEBUG_HEAVY

static void
SafenetPEC_DumpSA(
		  SafenetPEC_SA_t *SA_p, uint32_t type);

static void
SafenetPEC_DumpPktDescriptor(
			     PEC_CommandDescriptor_t *Descriptor_p,
			     void * SrcBuf_p);

static void
SafenetPEC_DumpResultPEPacket(
			      PE_PKT_DESCRIPTOR *PE_Packet_p);

#endif


/*---------------------------------------------------------------------------
 *  SafenetPEC_PopulateSA
 */
static inline bool
SafenetPEC_PopulateSA (
		       PE_SA_TYPE type,
		       PE_FLAGS flags,
		       SafenetPEC_SA_t *sa,
		       SafenetPEC_StateRecord_t *StateRec,
		       uint32_t spi,
		       uint32_t seq,
		       int hash_alg,
		       int ciph_alg,
		       unsigned char *ciph_key,
		       size_t ciph_key_len,
		       unsigned char *mac_key,
		       size_t mac_key_len)
{
    
  uint8_t HashAlgo = PEC_OPCODE_HASH_NULL;
  size_t DigestLen = 0; 
  unsigned char inner[20]; /* inner precompute for HMAC */
  unsigned char outer[20]; /* outer precompute for HMAC */

  memset(inner, 0, 20);
  memset(outer, 0, 20);

  /* Set the hash digest length  */
  if (hash_alg == PE_HASH_ALG_SHA1)
    DigestLen = 20;
  else if (hash_alg == PE_HASH_ALG_MD5)
    DigestLen = 16;
  else if (type == PE_SA_TYPE_AH)
    return false;
   
  /*  make hash precomputes */
  if (hash_alg != PE_HASH_ALG_NULL)
    {
      if (!ssh_safenet_compute_hmac_precomputes(
						hash_alg == PE_HASH_ALG_SHA1, 
						mac_key,
						mac_key_len,
						inner,
						outer))
        {
	  SSH_DEBUG(SSH_D_FAIL, ("safenet_pe_build_sa : "
				 "ssh_safenet_compute_hmac_precomputes failed.\n"));
	  return false;
        }
      safenet_copy_key_material(sa->InnerDigest, inner, DigestLen);
      safenet_copy_key_material(sa->OuterDigest, outer, DigestLen);
    }


  /* TODO: Add SSH_DEBUG messages for every 'return false'. */

  /* initialize state record */
  safenet_copy_key_material(StateRec->SaveDigest, sa->InnerDigest, DigestLen);
  StateRec->SaveHashByteCtr = 0;
    
  /* Initialize command0 and command1 words. */
  sa->Command0 = 0;
  sa->Command1 = 0;

  /* Set common fields */
  sa->SPI = (uint32_t)spi;
  sa->SequenceNum = (uint32_t)seq;

  /* Which hash algorithm is used */
  switch (hash_alg)
    {
    case PE_HASH_ALG_MD5:
      HashAlgo = PEC_OPCODE_HASH_MD5;
      break;
    case PE_HASH_ALG_SHA1:
      HashAlgo = PEC_OPCODE_HASH_SHA_1;
      break;
    case PE_HASH_ALG_NULL:
      HashAlgo = PEC_OPCODE_HASH_NULL;  
    default:
      SSH_DEBUG(SSH_D_FAIL, ("SafenetPEC_PopulateSA: "
			     "Unknown hash algorithm specified - %d\n",
			     hash_alg));
      return false;
    }

  /*  Set command words for AH */
  if (type == PE_SA_TYPE_AH)
    {
      uint8_t OpCode=0, Dir=0;
      if (flags & PE_FLAGS_OUTBOUND)
        {
	  OpCode = PEC_OPCODE_AH_OUTBOUND;
	  Dir = 0;
        }
      else
        {
	  OpCode = PEC_OPCODE_AH_INBOUND;
	  Dir = 1;
        }

      SafenetPEC_SA_SetCommand0(&sa->Command0,
				OpCode, /* OpCode  */
				Dir, /* Dir */
				0x1, /* OpGroup */
				SAFENET_PEC_PAD_IPSEC, /* Pad */
				PEC_OPCODE_CRYPT_NULL, /* Cipher */
				HashAlgo, /* Hash */
				0x0, /* SP */
				0x0, /* EP */
				0x1, /* HP */
				0x3, /* DigLen */
				0x0, /* LdIV */
				SAFENET_PEC_LOAD_HASH_STATE, /* LdHS */
				0x0, /* SvIV */
				0x1, /* SvHS */
				0x0, /* G */
				0x0 /* S */
				);

      SafenetPEC_SA_SetCommand1(&sa->Command1,
				0x01, /* CpHdr */
				0x01, /* CpPay */
				0x0, /* CpPad */
				(flags & PE_FLAGS_IPV6) ? 1 : 0, /* IPversion */
				0x0, /* MutBit */
				0x1, /* SNMask */
				0x0, /* ESN */
				0x0, /* CMode */
				0x0, /* FBMode */
				0x0, /* HMAC_MC */
				0x0, /* BOffset */
				0x0, /* SARev */
				0x0, /* HCOffset */
				0x0, /* KeyLen */
				0x0, /* ARC4SF */
				0x0, /* SvARC4 */
				0x0 /* CMode */
				);
                                  
    } /* Set command words and prepare keys for ESP operations */
  else
    {
      uint8_t OpCode=0, Dir=0, LoadIV=0, CipherAlgo=0, Keylen=0,
	CryptoMode=0, AESCtrMode=0;
      if (flags & PE_FLAGS_OUTBOUND)
        {
	  OpCode = PEC_OPCODE_ESP_OUTBOUND;
	  Dir = 0;
	  LoadIV = 0x0; 
        }
      else
        {
	  OpCode = PEC_OPCODE_ESP_INBOUND;
	  Dir = 1;
	  LoadIV = 0x1; 
        }
        
      /* We not always use CBC mode of encryption */
      if (hash_alg == PE_HASH_ALG_GCM)
        {
          /* We select AES-CTR (AES Counter Mode (CTR)
	     for IPSec using a 32-bit counter) */
          CryptoMode = 0;
          AESCtrMode = 1;
        }
      else
        {
          CryptoMode = 1;
          AESCtrMode = 0;
        }

      switch (ciph_alg)
        {
	case PE_CIPHER_ALG_DES:
	  CipherAlgo = PEC_OPCODE_CRYPT_DES;
	  break;
	case PE_CIPHER_ALG_TDES :
	  CipherAlgo = PEC_OPCODE_CRYPT_3DES;
	  break;
	case PE_CIPHER_ALG_AES:
	  CipherAlgo = PEC_OPCODE_CRYPT_AES;
	  {
	    if (ciph_key_len == 16)
	      Keylen = 0x2;
	    else if (ciph_key_len == 24)
	      Keylen = 0x3;
	    else if (ciph_key_len == 32)
	      Keylen = 0x4;
	    else
	      {
		SSH_DEBUG(SSH_D_FAIL,
			  ("SafenetPEC_PopulateSA: "
			   "Invalid cipher key length specified - %lu\n",
			   ciph_key_len));
                        
		return false;
	      }
	  }
	  break;
	case PE_CIPHER_ALG_NULL:
	  CipherAlgo = PEC_OPCODE_CRYPT_NULL;
	  break;
	default:
	  SSH_DEBUG(SSH_D_FAIL,
		    ("SafenetPEC_PopulateSA: "
		     " Unknown cipher algorithm specified - %d\n",
		     ciph_alg));

	  return false;
        }

      SafenetPEC_SA_SetCommand0(&sa->Command0,
				OpCode, /* OpCode */
				Dir, /* Dir */
				0x1, /* OpGroup */
				SAFENET_PEC_PAD_IPSEC, /* Pad */
				CipherAlgo, /* Cipher */
				HashAlgo, /* Hash */
				0x0, /* SP */
				0x0, /* EP */
				0x1, /* HP */
				0x3, /* DigLen */
				LoadIV, /* LdIV */
				SAFENET_PEC_LOAD_HASH_STATE, /* LdHS */
				0x0, /* SvIV */
				0x0, /* SvHS */
				0x0, /* G */
				0x0 /* S */
				);

      SafenetPEC_SA_SetCommand1(&sa->Command1,
				0x00, /* CpHdr */
				0x00, /* CpPay */
				0x0, /* CpPad */
				(flags & PE_FLAGS_IPV6) ? 1 : 0,/*IPversion*/
				0x1, /* MutBit */
				0x1, /* SNMask */
				0x0, /* ESN */
				CryptoMode, /* CMode */
				0x1, /* FBMode */
				0x1, /* HMAC_MC */
				0x0, /* BOffset */
				0x0, /* SARev */
				0x0, /* HCOffset */
				Keylen, /* KeyLen */
				0x0, /* ARC4SF */
				0x0, /* SvARC4 */
				AESCtrMode  /* CMode */
				);
        
      /* Copy key material to SA buffer */
      if (ciph_alg != PE_CIPHER_ALG_NULL)
	safenet_copy_key_material((uint8_t*)(sa->Key), ciph_key, ciph_key_len);
    }

#ifdef SAFENET_DEBUG_HEAVY
  SafenetPEC_DumpSA(sa, type); 
#endif
  
  return true;
}


/*----------------------------------------------------------------------------
 * SafenetPEC_PEPacketDescr_To_PECCommandDescr
 *
 */
static inline bool
SafenetPEC_PEPacketDescr_To_PECCommandDescr(
					    PEC_CommandDescriptor_t *Descriptor_p,
					    PE_PKT_DESCRIPTOR *pkt,
					    DMABuf_Handle_t SAHandle,
					    size_t SA_Size,
					    DMABuf_Handle_t SrecHandle)
{
  DMABuf_Handle_t SrcHandle;
  DMABuf_Properties_t SrcProperties;
  DMABuf_Status_t DMAStatus;

  SrcProperties.Size = pkt->src_len;
  SrcProperties.Alignment = 4;
  SrcProperties.fCached = true;
  SrcProperties.Bank = 0;

  /* Intialize packet descriptor word 0 */
  SafenetPEC_PacketDescriptor_SetWord0(&Descriptor_p->Control1,
				       (pkt->flags & PE_FLAGS_AES)?0x8:0, /* PadControl */
				       pkt->next_header,/* NextHeaderValue */
				       0x0, /* fInitARC4 */
				       0x1 /* fHashFinal */
				       );
  /* Register alien packet buffer */
  DMAStatus = DMABuf_Register(
			      SrcProperties,
			      pkt->src,
			      NULL, /* void * Alternative_p, */
			      'k',  /* const char AllocatorRef, */
			      &SrcHandle);
                                
  if (DMAStatus != DMABUF_STATUS_OK)
    {
      SSH_DEBUG(SSH_D_FAIL,
		("SafenetPEC_PEPacketDescr_To_PECCommandDescr : "
		 "DMABuf_Register failed with error %d",
		 DMAStatus));

      return false;
    }
    
  /* Initialize other descriptor fields */
  Descriptor_p->User_p = pkt->user_handle;
  Descriptor_p->SrcPkt_Handle = SrcHandle;
  Descriptor_p->DstPkt_Handle = SrcHandle;
  Descriptor_p->SrcPkt_ByteCount = pkt->src_len;
  Descriptor_p->SA_WordCount = SA_Size;
  Descriptor_p->SA_Handle1 = SAHandle;
  Descriptor_p->SA_Handle2 = SrecHandle;
  Descriptor_p->Control2 = 0;

#ifdef SAFENET_DEBUG_HEAVY
  SafenetPEC_DumpPktDescriptor(
			       Descriptor_p,
			       pkt->src);
#endif

  return true;
}


/*--------------------------------------------------------------------------
 * SafenetPEC_PECResultDescr_To_PEPacketDescr
 */
static inline void
SafenetPEC_PECResultDescr_To_PEPacketDescr(
					   PEC_ResultDescriptor_t *PEC_Descriptor,
					   PE_PKT_DESCRIPTOR *PE_Packet)
{
  uint8_t PadStatus=0, NextHeader_PadValue=0, Status=0;
    
  PE_Packet->user_handle = PEC_Descriptor->User_p; 
  PE_Packet->dst = PEC_Descriptor->DstPkt_p;
  PE_Packet->dst_len = PEC_Descriptor->DstPkt_ByteCount;
  PE_Packet->src_len = PEC_Descriptor->DstPkt_ByteCount;
    
  SafenetPEC_PacketDescriptor_GetWord0(PEC_Descriptor->Status1,
				       &PadStatus,
				       &NextHeader_PadValue,
				       &Status);
   
  PE_Packet->next_header = NextHeader_PadValue;
    
  if (Status)
    {
      PE_Packet->status = PE_PKT_STATUS_FAILURE;        
    }
  else
    PE_Packet->status = PE_PKT_STATUS_OK;

  SSH_DEBUG(SSH_D_HIGHOK,
	    ("SafenetPEC_PECResultDescr_To_PEPacketDescr : "
	     " PEC return code - %d\n",
	     Status));

#ifdef SAFENET_DEBUG_HEAVY
  SafenetPEC_DumpResultPEPacket(PE_Packet);
#endif

  DMABuf_Release(PEC_Descriptor->DstPkt_Handle);
}




#ifdef SAFENET_DEBUG_HEAVY
static const char *
SafenetPEC_GetHashAlgoStr(
			  uint32_t HashAlgo)
{
  switch (HashAlgo)
    {
    case PEC_OPCODE_HASH_MD5:
      return "MD5";
    case PEC_OPCODE_HASH_SHA_1:
      return "SHA-160";
    case PEC_OPCODE_HASH_SHA_224:
      return "SHA-224";
    case PEC_OPCODE_HASH_SHA_256:
      return "SHA-256";
    case PEC_OPCODE_HASH_SHA_384:
      return "SHA-384";
    case PEC_OPCODE_HASH_SHA_512:
      return "SHA-512";
    case PEC_OPCODE_HASH_NULL:
      return "NULL";
    default:
      return "Invalid hash algorithm.";

    }
}


static const char *
SafenetPEC_GetCipherAlgoStr(
			    uint32_t CipherAlgo)
{
  switch (CipherAlgo)
    {
    case PEC_OPCODE_CRYPT_DES:
      return "DES";
    case PEC_OPCODE_CRYPT_3DES:
      return "3DES";
    case PEC_OPCODE_CRYPT_ARC4:
      return "ARC4";
    case PEC_OPCODE_CRYPT_AES:
      return "AES";
    case PEC_OPCODE_CRYPT_NULL:
      return "NULL";
    default:
      return "Invalid cipher algorithm.";
    }
}


static const char *
SafenetPEC_GetCipherPadStr(
			   uint32_t Pad)
{
  switch (Pad)
    {
    case 0x0:
      return "IPSec";
    case 0x1:
      return "PKCS7";
    case 0x2:
      return "Constant pad";
    case 0x3:
      return "Zero pad";
    case 0x5:
      return "DTLS and TLS pad";
    case 0x6:
      return "Constant SSL pad";
    default:
      return "Invalid padding scheme";
    }
}


static const char *
SafenetPEC_GetOpgroupStr(
			 uint32_t OpGroup)
{
  switch (OpGroup)
    {
    case PEC_OPCODE_OPGROUP_BASIC_OP:
      return "Basic operation group.";
    case PEC_OPCODE_OPGROUP_PROTOCOL_OP:
      return "Protocol operation group";
    case PEC_OPCODE_OPGROUP_EXT_PROTOCOL_OP:
      return "Extended protocol operation group";
    case PEC_OPCODE_OPGROUP_RESERVED:
      return "Reserved";
    default:
      return "Invalid opgroup.";
    }
}


static const char *
SafenetPEC_GetDirectionStr(
			   uint32_t Dir)
{
  switch (Dir)
    {
    case 0:
      return "Outbound operation";
    case 1:
      return "Inbound operation";
    default:
      return "Invalid direction";
    }
}


static const char *
SafenetPEC_GetOpcodeStr(
			uint32_t Opcode, uint32_t type)
{
  if (type == PE_SA_TYPE_AH)
    {
      if (Opcode == PEC_OPCODE_AH_OUTBOUND)
	return "AH outbound";
      else
	return "AH inbound";
    }
  else
    {
      if (Opcode == PEC_OPCODE_ESP_OUTBOUND)
	return "ESP outbound";
      else
	return "ESP inbound";
    }
}


static const char *
SafenetPEC_GetLoadDigestStr(
			    uint32_t LoadDigest)
{
  switch (LoadDigest)
    {
    case 0x0:
      return "From SA";
    case 0x1:
      return "Reserved";
    case 0x2:
      return "From state";
    case 0x3:
      return "No load";
    default:
      return "Unknown value";
    }
}


static const char *
SafenetPEC_GetSaveDigestStr(
			    uint32_t SaveDigest)
{
  if (SaveDigest)
    return "Hash state is saved.";
  else
    return "Hash state is not saved";
}


static const char *
SafenetPEC_GetSaveIVStr(
			uint32_t SaveIV)
{
  if (SaveIV)
    return "IV is saved.";
  else
    return "IV is not saved";
}


static const char *
SafenetPEC_GetLoadIVStr(
			uint32_t LoadIV)
{
  switch (LoadIV)
    {
    case 0x0:
      return "Previous result IV";
    case 0x1:
      return "Input buffer";
    case 0x2:
      return "Saved IV";
    case 0x3:
      return "Automatically";
    default:
      return "Unknown value";
    }
}


static const char *
SafenetPEC_GetCryptoModeStr(
			    uint32_t Mode)
{
  switch (Mode)
    {
    case 0x0:
      return "ECB";
    case 0x1:
      return "CBC";
    case 0x2:
      return "OFB";
    case 0x3:
      return "CFB";
    case 0x4:
      return "CTR";
    case 0x5:
      return "ICM";
    default:
      return "Invalid value.";
    }
}


static const char *
SafenetPEC_GetFeedbackStr(
			  uint32_t FeedbackMode)
{
  switch (FeedbackMode)
    {
    case 0x0:
      return "64 bit OFB";
    case 0x1:
      return "8 bit CFB";
    case 0x2:
      return "1 bit CFB";
    case 0x3:
      return "128 bit CFB";
    default:
      return "Invalid feedback mode";
    }

}


static const char *
SafenetPEC_GetHmacMCStr(
			uint32_t HMAC_MC)
{
  if (HMAC_MC)
    return "Enable mutable bit processing";
  else
    return "Disable mutable bit processing";
}

/*---------------------------------------------------------------------------
 *  * SafenetPEC_DumpSA
 *   */
static void 
SafenetPEC_DumpSA(
		  SafenetPEC_SA_t *SA_p, uint32_t type)
{
  uint8_t OpCode=0, Dir=0, OpGroup=0, Pad=0, Cipher=0, Hash=0, SP=0,
    EP=0, HP=0, DigLen=0, LdIV=0, LdHS=0, SvIV=0, SvHS=0, G=0, S=0;
  
  uint8_t CpHdr=0, CpPay=0, CpPad=0, IPversion=0, MutBit=0,
    SNMask=0, ESN=0, CMode=0, FBMode=0, HMAC_MC=0, BOffset=0,
    SARev=0, HCOffset=0, KeyLen=0, ARC4SF=0, SvARC4=0, CModeEx=0;

  SafenetPEC_SA_GetCommand0(SA_p->Command0,
			    &OpCode,
			    &Dir,
			    &OpGroup,
			    &Pad,
			    &Cipher,
			    &Hash,
			    &SP,
			    &EP,
			    &HP,
			    &DigLen,        
			    &LdIV,
			    &LdHS,
			    &SvIV,
			    &SvHS,
			    &G,
			    &S);

  SafenetPEC_SA_GetCommand1(SA_p->Command1,
			    &CpHdr,
			    &CpPay,
			    &CpPad,
			    &IPversion,
			    &MutBit,
			    &SNMask,
			    &ESN,
			    &CMode,
			    &FBMode,
			    &HMAC_MC,        
			    &BOffset,
			    &SARev,
			    &HCOffset,
			    &KeyLen,
			    &ARC4SF,
			    &SvARC4,
			    &CModeEx);

  SSH_DEBUG(SSH_D_HIGHOK, ("SafenetPEC_DumpSA : \n"));

  SSH_DEBUG(SSH_D_HIGHOK,
	    ("Command0 : \n"
             "    Opcode - 0x%02x (%s)\n"
             "    Direction - %d (%s)\n"
             "    OpGroup - 0x%02x (%s)\n"
             "    Padding - 0x%04x (%s)\n"
             "    Cipher algorithm - 0x%04x (%s)\n"
             "    Hash algorithm - 0x%04x (%s)\n"
             "    Header processing - %d\n"
             "    DigestLen - %d\n"
             "    Load IV - 0x%02x (%s)\n"
             "    Save IV - 0x%02x (%s)\n"
             "    Load Digest - 0x%02x (%s)\n"
             "    Save Digest - 0x%02x (%s)\n",
             OpCode, 
             SafenetPEC_GetOpcodeStr(
				     OpCode, type),
             Dir, 
             SafenetPEC_GetDirectionStr(Dir),
             OpGroup, 
             SafenetPEC_GetOpgroupStr(OpGroup),
             Pad + EP,
             SafenetPEC_GetCipherPadStr(
					Pad + EP),
             Cipher,
             SafenetPEC_GetCipherAlgoStr(Cipher),
             Hash,
             SafenetPEC_GetHashAlgoStr(Hash),
             HP,
             DigLen,
             LdIV,
             SafenetPEC_GetLoadIVStr(LdIV),             
             SvIV,
             SafenetPEC_GetSaveIVStr(SvIV),
             LdHS,
             SafenetPEC_GetLoadDigestStr(LdHS),
             SvHS,
	     SafenetPEC_GetSaveDigestStr(SvHS)));

  SSH_DEBUG(SSH_D_HIGHOK,
	    ("Command1 : \n"
             "    CopyHeader - %d\n"
             "    CopyPayload - %d\n"
             "    CopyPad - %d\n"
             "    IPVersion - %d\n"
             "    Mutable bit processing - %d\n"
             "    Sequence number mask - %d\n"
             "    Extended sequence number mask - %d\n"
             "    Crypto mode - 0x%x (%s)\n"
             "    Feedback mode - 0x%x (%s)\n"
             "    HMAC/MC - %d (%s)\n"
             "    SA revision - %d\n"
             "    Cipher key length - %d\n",
             CpHdr,
             CpPay,
             CpPad,
             IPversion,
             MutBit,
             SNMask,
             ESN,
             CMode + CModeEx,
             SafenetPEC_GetCryptoModeStr(CMode + CModeEx),
             FBMode,
             SafenetPEC_GetFeedbackStr(FBMode),
             HMAC_MC,
             SafenetPEC_GetHmacMCStr(HMAC_MC),
             SARev,
	     KeyLen));

  SSH_DEBUG_HEXDUMP(SSH_D_HIGHOK,
		    ("Key : "), (uint8_t*)(SA_p->Key), KeyLen);
  SSH_DEBUG_HEXDUMP(SSH_D_HIGHOK,
		    ("Inner digest : "), SA_p->InnerDigest, 20);
  SSH_DEBUG_HEXDUMP(SSH_D_HIGHOK,
		    ("Outer digest : "), SA_p->OuterDigest, 20);

  SSH_DEBUG(SSH_D_HIGHOK,
            ("SPI - 0x%08x\n"
	     "Sequence number - 0x%08x\n"
	     "Sequence number mask0 - 0x%08x\n"
	     "Sequence number mask1 - 0x%08x\n"
	     "Nonce - 0x%08x\n"
	     "State record address - 0x%08x\n",
	     SA_p->SPI, SA_p->SequenceNum, 
	     SA_p->SeqNumMask0, SA_p->SeqNumMask1,
	     SA_p->Nonce, SA_p->StatePtr));
}


static void
SafenetPEC_DumpPktDescriptor(
			     PEC_CommandDescriptor_t *Descriptor_p,
			     void *SrcBuf_p)
{
  SSH_DEBUG_HEXDUMP(SSH_D_HIGHOK,
		    ("Source buffer"),
		    (uint8_t *)SrcBuf_p,
		    Descriptor_p->SrcPkt_ByteCount);
  SSH_DEBUG(SSH_D_HIGHOK,
	    ("Command Descriptor : \n"
	     "   User handle - 0x%p\n"
	     "   Src packet handle - 0x%p\n"
	     "   Dst packet handle - 0x%p\n"
	     "   Source packet length - %d\n"
	     "   SA Length - %d\n"
	     "   SA Handle - 0x%p\n"
	     "   State record handle - 0x%p\n"
	     "   Control word 0 - 0x%x"
	     "   Control word 1 - 0x%x\n",
	     Descriptor_p->User_p,
	     Descriptor_p->SrcPkt_Handle.p,
	     Descriptor_p->DstPkt_Handle.p,
	     Descriptor_p->SrcPkt_ByteCount,
	     Descriptor_p->SA_WordCount,
	     Descriptor_p->SA_Handle1.p,
	     Descriptor_p->SA_Handle2.p,
	     Descriptor_p->Control1,
	     Descriptor_p->Control2));
}


static void 
SafenetPEC_DumpResultPEPacket(
			      PE_PKT_DESCRIPTOR *PE_Packet_p)
{
  SSH_DEBUG(SSH_D_HIGHOK,
	    ("Result PE Packet :\n"
             "    user handle - 0x%p\n"
             "    destination address - 0x%p\n"
             "    destination byte count - %lu\n"
             "    source byte count - %lu\n",
             PE_Packet_p->user_handle,
             PE_Packet_p->dst,
             PE_Packet_p->dst_len,
	     PE_Packet_p->src_len));

  SSH_DEBUG_HEXDUMP(SSH_D_HIGHOK,
		    ("Destination PE Packet"),
		    PE_Packet_p->dst,
		    PE_Packet_p->dst_len);
}
#endif /* #ifdef SAFENET_DEBUG */



#endif /* SAFENET_PE_PEC_1742_H */

/* end of safenet_pe_pec_1742.h */

