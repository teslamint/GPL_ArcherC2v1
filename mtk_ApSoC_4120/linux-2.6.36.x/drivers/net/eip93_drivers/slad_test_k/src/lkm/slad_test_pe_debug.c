/***********************************************************
*
* SLAD Test Application
*
*

     Copyright 2007-2008 SafeNet Inc



*
* Edit History:
*
*Initial revision
* Created.
**************************************************************/
#include "slad_test_pe.h"
#ifdef SLAD_TEST_BUILD_FOR_PE

#include "slad_test.h"
#include "slad_test_pe_debug.h"
#ifndef USE_NEW_API
#include "slad.h"
#endif
#include "slad_osal.h"


#ifndef IDENTIFIER_NOT_USED
#define IDENTIFIER_NOT_USED(_v) if(_v){}
#endif


/***************************************************************
*
****************************************************************/
void
slad_test_print_hex (void *s, int len_in_bytes)
{
  int i = 0;
  BYTE *d;
  d = (BYTE *) s;

  for (i = 0; i < len_in_bytes; i++)
    {
      if (i % 16 == 0)
        LOG_INFO ("\n\t");
      if (i % 4 == 0)
        LOG_INFO ("\t");
      LOG_INFO ("%02x ", *(d++));
    }

  LOG_INFO ("\n");
}

/****************************************************************/


void
slad_test_print_word_in_bits (UINT32 word)
{
  int i;

  LOG_INFO
    ("\n---------------------------------------------------------\n");

  for (i = 31; i >= 0; i--)
    {
      if (((i + 1) % 4) == 0)
        {
          if (i != 31)
            LOG_INFO (" ");
          LOG_INFO ("%2d", i);
        }
      else if (((i % 4) == 0))
        {
          //LOG_INFO(" ");
          LOG_INFO ("%2d", i);
        }
      else
        {
          LOG_INFO ("  ");
        }
    }

  LOG_INFO
    ("\n----------------------------------------------------------\n");

  for (i = 31; i >= 0; i--)
    {
      if (((i + 1) % 4 == 0) && (i != 31))
        LOG_INFO (" ");
      if (word >> 31)
        LOG_INFO (" 1");
      else
        LOG_INFO (" 0");

      word <<= 1;
    }
  LOG_INFO
    ("\n----------------------------------------------------------\n\n");

}


void
slad_test_print_descriptor_rev0 (void *pd_or_rd)
{
  UINT32 *d;
  d = (UINT32 *) pd_or_rd;

  LOG_INFO ("\n{ ->: Rev 0 Descriptor -----------------------------\n");

  LOG_INFO ("\n First Word in bits : \n");
  slad_test_print_word_in_bits (d[0]);

  LOG_INFO ("\n Pad Control/Status : %x \t", (d[0] >> 24));
  LOG_INFO (" Status : %x \t", (d[0] >> 16) & 0xff);
  LOG_INFO (" Next Header/Pad : %x \t", (d[0] >> 8) & 0xff);
  LOG_INFO (" Control : %x ", (d[0] & 0xff));

  LOG_INFO ("\n Source Address : %x ", d[1]);
  LOG_INFO ("\n Destination Address : %x ", d[2]);
  LOG_INFO ("\n SA Handle : %x ", d[3]);

  LOG_INFO ("\n Last Word in bits : \n");
  slad_test_print_word_in_bits (d[4]);

  LOG_INFO ("\n Bypass : %x ", (d[4] >> 24));
  LOG_INFO ("\t Control 2 : %x ", (d[4] >> 20) & 0xf);
  LOG_INFO ("\t Packet Length ( bytes ) in decimal : %u \n",
            (d[4] & 0xfffff));

  LOG_INFO ("\n} :<- ENDS Rev 0 Descriptor ------------------------\n");


}

void
slad_test_print_descriptor_rev1 (void *pd_or_rd)
{
  UINT32 *d;
  d = (UINT32 *) pd_or_rd;

  LOG_INFO ("\n{ ->: Rev 1 Descriptor ( for Dynamic SA ) ------------\n");

  LOG_INFO ("\n First Word in bits : \n");
  slad_test_print_word_in_bits (d[0]);

  LOG_INFO ("\n Pad Control/Status : %x \t", (d[0] >> 24));
  LOG_INFO (" Status : %x \t", (d[0] >> 16) & 0xff);
  LOG_INFO (" Next Header/Pad : %x \t", (d[0] >> 8) & 0xff);
  LOG_INFO (" Control : %x ", (d[0] & 0xff));

  LOG_INFO ("\n Source Address : %x ", d[1]);
  LOG_INFO ("\n Destination Address : %x ", d[2]);
  LOG_INFO ("\n SA Handle : %x ", d[3]);
  LOG_INFO ("\n SA Length ( in Words) in decimal: %u ", d[4]);

  LOG_INFO ("\n Last Word in bits : \n");
  slad_test_print_word_in_bits (d[5]);

  LOG_INFO ("\n Bypass : %x ", (d[5] >> 24));
  LOG_INFO ("\t Control 2 : %x ", (d[5] >> 20) & 0xf);
  LOG_INFO ("\t Packet Length ( bytes ) in decimal : %u \n",
            (d[5] & 0xfffff));

  LOG_INFO ("\n} :<- ENDS Rev 1 ( for Dynamic SA ) Descriptor ----------\n");


}

void
slad_test_print_descriptor (void *pd_or_rd, int rev)
{
  switch (rev)
    {
    case 0:
      slad_test_print_descriptor_rev0 (pd_or_rd);
      break;

    case 1:
      // Dynamic SA
      slad_test_print_descriptor_rev1 (pd_or_rd);
      break;
    default:
      LOG_INFO
        ("\n Invalid Descriptor Revision Type. Can't print descriptor. \n");
    }
}

void
slad_test_print_decode_sa_command0 (UINT32 cmd)
{
  unsigned char OpCode, Dir, OpGroup, Pad, Cipher, Hash, SP,
    EP, HP, DigLen, Ld_IV, Ld_HS, Sv_IV, Sv_HS, G, S;
  unsigned int aggregate_pad_type;

  char *basic_op_strings_ob[] = {
    "Encrypt", "Encrypt-Hash", "Reserved ( Compress )", "Hash",
    "Reserved ( Hash-Encrypt )", "Reserved", "Reserved", "Reserved"
  };

  char *basic_op_strings_ib[] = {
    "Decrypt", "Hash-Decrypt", "Reserved ( Decompress )", "Hash",
    "Reserved ( Decrypt-Hash )", "Reserved", "Reserved", "Reserved"
  };

  char *proto_op_strings_ob[] = {
    "ESP Outbound", "AH Outbound", "Reserved for Ipcomp", "Reserved for MPPE",
    "SSL Outbound", "TLS Outbound", "Reserved for WTLS", "SRTP Outbound"
  };

  char *proto_op_strings_ib[] = {
    "ESP Inbound", "AH Inbound", "Reserved for Ipcomp", "Reserved for MPPE",
    "SSL Inbound", "TLS Inbound", "Reserved for WTLS", "SRTP Inbound"
  };

  char *extended_proto_strings_ob[] = {
    "Reserved", "DTLS Outbound", "MACSec Outbound", "Reserved",
    "SSL Outbound", "TLS v1.0 Outbound", "TLS v1.1 Outbound", "Reserved"
  };

  char *extended_proto_strings_ib[] = {
    "Reserved", "DTLS Inbound", "MACSec Inbound", "Reserved",
    "SSL Inbound", "TLS v1.0 Inbound", "TLS v1.1 Inbound", "Reserved"
  };

  char *cipher_strings[] = {
    "DES", "Triple-DES", "ARC4", "AES",
    "Reserved", "Reserved", "Reserved", "Reserved",
    "Reserved", "Reserved", "Reserved", "Reserved",
    "Reserved", "Reserved", "Reserved", "Null"
  };

  char *hash_strings[] = {
    "MD5", "SHA-1", "SHA2-224", "SHA2-256",
    "SHA2-384", "SHA-512", "Reserved", "Reserved",
    "AES-XCBC-MAC-128 bit key", "Reserved", "Reserved", "Reserved",
    "GHASH (selected in combination with AES-CTR = CCM)", "GMAC",
    "CBC-MAC (selected in combination with AES-CTR = CCM)", "Null"
  };

  char *DigLen_Strings[] = {
    "No hash digest output", "1 word", "2 words", "3 words",
    "4 words", "Reserved", "Reserved", "Reserved",
    "Reserved", "Reserved", "Reserved", "Reserved",
    "Reserved", "Reserved", "Reserved", "Reserved"
  };

  char *pad_type_strings[] = {
    "IPSec", "PKCS#7", "Constant Pad", "Zero Pad",
    "TLS Pad" "Constant SSL Pad", "", ""
  };

  char *load_iv_strings[] = {
    "From SA", "Input Buffer", "Saved IV", "Automatically"
  };

  char *load_hash_state_strings[] = {
    "From SA", "Reserved", "From State", "No Load"
  };

  IDENTIFIER_NOT_USED (load_hash_state_strings[0]);
  IDENTIFIER_NOT_USED (load_iv_strings[0]);
  IDENTIFIER_NOT_USED (DigLen_Strings[0]);
  IDENTIFIER_NOT_USED (hash_strings[0]);
  IDENTIFIER_NOT_USED (cipher_strings[0]);
  IDENTIFIER_NOT_USED (extended_proto_strings_ib[0]);
  IDENTIFIER_NOT_USED (extended_proto_strings_ob[0]);
  IDENTIFIER_NOT_USED (proto_op_strings_ib[0]);
  IDENTIFIER_NOT_USED (proto_op_strings_ob[0]);
  IDENTIFIER_NOT_USED (basic_op_strings_ib[0]);
  IDENTIFIER_NOT_USED (basic_op_strings_ob[0]);

  OpCode = cmd & 0x7;
  Dir = (cmd >> 3) & 0x1;
  OpGroup = (cmd >> 4) & 0x3;
  Pad = (cmd >> 6) & 0x3;
  Cipher = (cmd >> 8) & 0xf;
  Hash = (cmd >> 12) & 0xf;
  SP = (cmd >> 17) & 0x1;
  EP = (cmd >> 18) & 0x1;
  HP = (cmd >> 19) & 0x1;
  DigLen = (cmd >> 20) & 0xf;
  Ld_IV = (cmd >> 24) & 0x3;
  Ld_HS = (cmd >> 26) & 0x3;
  Sv_IV = (cmd >> 28) & 0x1;
  Sv_HS = (cmd >> 29) & 0x1;
  G = (cmd >> 30) & 0x1;
  S = (cmd >> 31) & 0x1;

  LOG_INFO ("\n{ ->:---- Decoding of SA Command 0 :----------------------\n");
  switch (OpGroup)
    {
    case 0x0:
      LOG_INFO ("\n   Basic Operation -");

      if (Dir)
        {
          LOG_INFO ("\n\t   Direction : Inbound ");
          LOG_INFO ("\n\t   Operation : %s \n", basic_op_strings_ib[OpCode]);
        }
      else
        {
          LOG_INFO ("\n\t   Direction : Outbound ");
          LOG_INFO ("\n\t   Operation : %s \n", basic_op_strings_ob[OpCode]);
        }

      break;
    case 0x1:
      LOG_INFO ("\n   Protocol Operation - ");

      if (Dir)
        {
          LOG_INFO ("\n\t   Direction : Inbound ");
          LOG_INFO ("\n\t   Protocol  : %s \n", proto_op_strings_ib[OpCode]);
        }
      else
        {
          LOG_INFO ("\n\t   Direction : Outbound ");
          LOG_INFO ("\n\t   Protocol  : %s \n", proto_op_strings_ob[OpCode]);
        }



      break;

    case 0x3:
      LOG_INFO ("\n   Extended Protocol Operation - ");

      if (Dir)
        {
          LOG_INFO ("\n\t   Direction         : Inbound ");
          LOG_INFO ("\n\t   Extended Protocol : %s \n",
                    extended_proto_strings_ib[OpCode]);

        }
      else
        {
          LOG_INFO ("\n\t   Direction         : Outbound ");
          LOG_INFO ("\n\t   Extended Protocol : %s \n",
                    extended_proto_strings_ob[OpCode]);

        }

      break;

    default:
      LOG_INFO ("\n** Invalid Code for operation or protocol group\n");
      break;


    }

  aggregate_pad_type = ((EP << 3) | (Pad)) & 0x7;

  if (aggregate_pad_type <
      (sizeof (pad_type_strings) / sizeof (pad_type_strings[0])))
    LOG_INFO ("\n  Padding Type is : %s ",
              pad_type_strings[aggregate_pad_type]);

  LOG_INFO ("\n\n  Cipher is       : %s ", cipher_strings[Cipher]);
  LOG_INFO ("\n\n  Hash   is       : %s \n", hash_strings[Hash]);

  if (SP)
    LOG_INFO ("\n  Stream Cipher Padding : ENABLED \n");
  else
    LOG_INFO ("\n  Stream Cipher Padding : DISABLED \n");

  if (HP)
    LOG_INFO ("\n  Header Processing : ENABLED \n");
  else
    LOG_INFO ("\n  Header Processing : DISABLED \n");

  LOG_INFO ("\n  Digest Length is : %s \n", DigLen_Strings[DigLen]);
  LOG_INFO ("\n  Load IV          : %s \n", load_iv_strings[Ld_IV]);
  LOG_INFO ("\n  Load Hash State  : %s \n", load_hash_state_strings[Ld_HS]);

  if (Sv_IV)
    LOG_INFO ("\n  Save IV : Yes : IV is to be saved in State Record \n");
  else
    LOG_INFO ("\n  Save IV : No  : IV is not to be saved in State Record \n");

  if (Sv_HS)
    LOG_INFO
   ("\n  Save Hash State : Hash state is to be saved.\n");
   
  else
    LOG_INFO ("\n  Save Hash State : Hash state is NOT to be saved \n");

  if (G)
    LOG_INFO
 ("\n  Gather : Yes : Input to be gathered from memory \n");
  else
    LOG_INFO ("\n  Gather : No  : Input data is contigous in memory \n");

  if (S)
    LOG_INFO
      ("\n  Scatter : Yes : Output to be scattered in memory \n");
  else
    LOG_INFO
      ("\n  Scatter : No  : Output to be contigous in memory  \n");

  LOG_INFO ("\n} <- : DONE - Decoding of SA Command 0 :------------------\n");

}

void
slad_test_print_decode_sa_command1 (UINT32 cmd)
{
  unsigned char CpHdr, CpPay, CpPad, IPversion, MutBit, SNMask, ESN,
    CMode, FBMode, HMAC_MC, BOffset, SARev, HCOffset, KeyLen,
    ARC4SF, SvARC4, CMode_32;

  unsigned char aggregate_crypto_mode;

  CpHdr = (cmd >> 1) & 0x1;
  CpPay = (cmd >> 2) & 0x1;
  CpPad = (cmd >> 3) & 0x1;
  IPversion = (cmd >> 4) & 0x1;
  MutBit = (cmd >> 5) & 0x1;
  SNMask = (cmd >> 6) & 0x1;
  ESN = (cmd >> 7) & 0x1;
  CMode = (cmd >> 8) & 0x3;
  FBMode = (cmd >> 10) & 0x3;
  HMAC_MC = (cmd >> 12) & 0x1;
  BOffset = (cmd >> 13) & 0x1;
  SARev = (cmd >> 14) & 0x1;
  HCOffset = (cmd >> 16) & 0xff;
  KeyLen = (cmd >> 24) & 0x1f;
  ARC4SF = (cmd >> 29) & 0x1;
  SvARC4 = (cmd >> 30) & 0x1;
  CMode_32 = (cmd >> 31) & 0x1;

  aggregate_crypto_mode = ((CMode_32 << 3) | (CMode)) & 0x7;

  LOG_INFO ("\n{ ->:---- Decoding of SA Command 1 :---------------------\n");

  if (CpHdr)
    LOG_INFO ("\n\t Copy Header : Yes \n");
  else
    LOG_INFO ("\n\t Copy Header : No \n");

  if (CpPay)
    LOG_INFO ("\n\t Copy Payload : Yes \n");
  else
    LOG_INFO ("\n\t Copy Payload : No \n");

  if (CpPad)
    LOG_INFO ("\n\t Copy Pad ( for Inbound operation ) : Yes \n");
  else
    LOG_INFO ("\n\t Copy Pad ( for Inbound operation ) : No \n");

  if (IPversion)
    LOG_INFO
 ("\n\t IP Version ( Only for IPSec AH mutable bit processing ) : IPv6 \n");
  else
    LOG_INFO
 ("\n\t IP Version ( Only for IPSec AH mutable bit processing ) : IPv4 \n");

  if (MutBit)
    LOG_INFO ("\n\t Mutable Bit Processing : ENABLED \n");
  else
    LOG_INFO ("\n\t Mutable Bit Processing : DISABLED \n");

  if (SNMask)
 LOG_INFO ("\n\t Sequence Number Mask Size( for IPSEC only ) : 64-bit \n");
  else
    LOG_INFO
 ("\n\t Sequence Number Mask Size( for IPSEC only ) : 128-bit \n");

  if (ESN)
    LOG_INFO
      ("\n\t Extended Sequence Numbers size ( for IPSEC only ) : 64 -bit \n");
  else
    LOG_INFO
      ("\n\t Extended Sequence Numbers size ( for IPSEC only ) : 32 -bit \n");


  if (aggregate_crypto_mode == 0)
    LOG_INFO ("\n\t DES/AES Electronic Code Book (ECB) \n");
  else if (aggregate_crypto_mode == 1)
    LOG_INFO ("\n\t DES/AES Cipher Block Chaining (CBC) \n");
  else if (aggregate_crypto_mode == 2)
    LOG_INFO ("\n\t DES 64-bit Output Feedback Mode (OFB) \n");
  else if (aggregate_crypto_mode == 3)
    {
      if (FBMode == 1)
        LOG_INFO ("\n\t DES/AES 8-bit Cipher Feedback Mode (CFB) \n");

      if (FBMode == 2)
        LOG_INFO ("\n\t DES/AES 1-bit Cipher Feedback Mode (CFB) \n");

      if (FBMode == 3)
        LOG_INFO ("\n\t AES 128-bit Cipher Feedback Mode (CFB) \n");
    }
  else if (aggregate_crypto_mode == 4)
    LOG_INFO
      ("\n\t AES Counter Mode (CTR) for IPSec using a 32-bit counter \n");
  else if (aggregate_crypto_mode == 5)
    LOG_INFO
("\n\t AES Integer Counter Mode (ICM) for SRTP using a 16-bit counter \n");
  else
    LOG_INFO ("\n\t Reserved \n");

  if (HMAC_MC)
    {
      LOG_INFO
 ("\n\tFor Basic Operations-HMAC processing( Hashfinal bit set) :ENABLED\n");
      LOG_INFO ("\n\t For AH : Disable mutable-bit processing \n");
    }
  else
    {
      LOG_INFO
        ("\n\t For Basic Operations - Standard Hash ( No HMAC processing ) \n");
      LOG_INFO
("\n\t For AH : Enable mutable-bit processing on options and ext headers \n");
    }

  if (BOffset)
    LOG_INFO ("\n\t For MACSEC only - HCOffset is defined in 8-bit bytes \n");
  else
    LOG_INFO
      ("\n\t For MACSEC only - HCOffset is defined in 32-bit words \n");

  if (SARev)
    LOG_INFO ("\n\t SA Revision 2 \n");
  else
    LOG_INFO ("\n\t SA Revision 1 \n");

  LOG_INFO ("\n\t HCOffset : %d \n", HCOffset);

  LOG_INFO ("\n\t KeyLen for AES and ARC4 only : \n");
  LOG_INFO ("\n\t\t For AES : ");
  if ((KeyLen == 0) || (KeyLen == 1))
    LOG_INFO ("\n\t\t\t Reserved \n");
  else if (KeyLen == 2)
    LOG_INFO ("\n\t\t\t 128 bits \n");
  else if (KeyLen == 3)
    LOG_INFO ("\n\t\t\t 192 bits \n");
  else if (KeyLen == 4)
    LOG_INFO ("\n\t\t\t 256 bits \n");
  else
    LOG_INFO ("\n\t\t\t Reserved \n");

  LOG_INFO ("\n\t\t For ARC4 : %d \n", KeyLen * 8);



  if (ARC4SF)
    LOG_INFO ("\n\t For ARC4 only : Stateful mode \n ");
  else
    LOG_INFO ("\n\t For ARC4 only : Stateless mode \n ");

  if (SvARC4)
    LOG_INFO ("\n\t For ARC4 only : ARC4 state is saved \n ");
  else
    LOG_INFO ("\n\t For ARC4 only : ARC4 state is NOT saved \n ");


  LOG_INFO
    ("\n\n} <- : DONE - Decoding of SA Command 1 :-----------------\n");

}

void
slad_test_print_sa_rev1 (void *sa_rev1)
{
  UINT32 *sa;
  sa = (UINT32 *) sa_rev1;
  LOG_INFO ("\n { ->: SA Rev1 ------------------------------------------ \n");

  LOG_INFO ("\n Command_0 :    %x ", sa[0]);
  LOG_INFO ("\n Command_0 in bits : \n");
  slad_test_print_word_in_bits (sa[0]);
  slad_test_print_decode_sa_command0 (sa[0]);

  LOG_INFO ("\n Command_1 :    %x ", sa[1]);
  LOG_INFO ("\n Command_1 in bits : \n");
  slad_test_print_word_in_bits (sa[1]);
  slad_test_print_decode_sa_command1 (sa[1]);


  LOG_INFO ("\n DESKey1_0 / AESKey_0 :    %x ", sa[4]);
  LOG_INFO ("\n DESKey1_1 / AESKey_1 :    %x ", sa[5]);
  LOG_INFO ("\n DESKey2_0 / AESKey_2 :    %x ", sa[6]);
  LOG_INFO ("\n DESKey2_1 / AESKey_3 :    %x ", sa[7]);
  LOG_INFO ("\n DESKey3_0 / AESKey_4 :    %x ", sa[8]);
  LOG_INFO ("\n DESKey3_1 / AESKey_5 :    %x ", sa[9]);
  LOG_INFO ("\n AESKey_6 :    %x ", sa[10]);
  LOG_INFO ("\n AESKey_7 :    %x ", sa[11]);

  LOG_INFO ("\n");

  LOG_INFO ("\n InnerDigest_0 (A) :    %x ", sa[12]);
  LOG_INFO ("\n InnerDigest_1 (B) :    %x ", sa[13]);
  LOG_INFO ("\n InnerDigest_2 (C) :    %x ", sa[14]);
  LOG_INFO ("\n InnerDigest_3 (D) :    %x ", sa[15]);
  LOG_INFO ("\n InnerDigest_4 (E) :    %x ", sa[16]);

  LOG_INFO ("\n");

  LOG_INFO ("\n OuterDigest_0 (A) :    %x ", sa[17]);
  LOG_INFO ("\n OuterDigest_1 (B) :    %x ", sa[18]);
  LOG_INFO ("\n OuterDigest_2 (C) :    %x ", sa[19]);
  LOG_INFO ("\n OuterDigest_3 (D) :    %x ", sa[20]);
  LOG_INFO ("\n OuterDigest_4 (E) :    %x ", sa[21]);

  LOG_INFO ("\n\n SPI :    %x \n", sa[22]);

  LOG_INFO ("\n SeqNum : %x \n", sa[23]);
  LOG_INFO ("\n SeqNumMask_0 : %x ", sa[24]);
  LOG_INFO ("\n SeqNumMask_1 : %x ", sa[25]);
  LOG_INFO ("\n Nonce : %x ", sa[26]);
  LOG_INFO ("\n\n StatePntr : %x \n", sa[27]);
  LOG_INFO ("\n ARC4ijPntr[15:0] : %x ", sa[28] & 0xffff);
  LOG_INFO ("\n\n ARC4_StatePntr : %x \n", sa[29]);

  LOG_INFO ("\n SAManagementField_0 : %x ", sa[30]);
  LOG_INFO ("\n SAManagementField_1 : %x \n", sa[31]);

  LOG_INFO ("\n } :<- ENDS SA Rev1 ------------------------------------- \n");

}

void
slad_test_print_srec_rev1 (void *srec_rev1)
{
  UINT32 *srec;
  srec = (UINT32 *) srec_rev1;

  LOG_INFO
    ("\n { ->:  State Record Rev 1 ---------------------------------\n");

  LOG_INFO ("\n SaveIV_0 : %x ", srec[0]);
  LOG_INFO ("\n SaveIV_1 : %x ", srec[1]);
  LOG_INFO ("\n SaveIV_2 : %x ", srec[2]);
  LOG_INFO ("\n SaveIV_3 : %x ", srec[3]);
  LOG_INFO ("\n SaveHashByteCntr : %x ", srec[4]);

  LOG_INFO ("\n SaveDigest_0 (A) : %x ", srec[5]);
  LOG_INFO ("\n SaveDigest_1 (B) : %x ", srec[6]);
  LOG_INFO ("\n SaveDigest_2 (C) : %x ", srec[7]);
  LOG_INFO ("\n SaveDigest_3 (D) : %x ", srec[8]);
  LOG_INFO ("\n SaveDigest_4 (E) : %x \n", srec[9]);

  LOG_INFO
    ("\n } :<-  ENDS State Record Rev 1 ----------------------------\n");

}

void
slad_test_print_sa_rev2 (void *sa_rev2)
{
  UINT32 *sa;
  sa = (UINT32 *) sa_rev2;
  LOG_INFO ("\n { ->: SA Rev2 ------------------------------------------ \n");

  LOG_INFO ("\n Command_0 :    %x ", sa[0]);
  LOG_INFO ("\n Command_0 in bits : \n");
  slad_test_print_word_in_bits (sa[0]);
  slad_test_print_decode_sa_command0 (sa[0]);

  LOG_INFO ("\n Command_1 :    %x ", sa[1]);
  LOG_INFO ("\n Command_1 in bits : \n");
  slad_test_print_word_in_bits (sa[1]);
  slad_test_print_decode_sa_command1 (sa[1]);

  LOG_INFO ("\n DESKey1_0 / AESKey_0 :    %x ", sa[4]);
  LOG_INFO ("\n DESKey1_1 / AESKey_1 :    %x ", sa[5]);
  LOG_INFO ("\n DESKey2_0 / AESKey_2 :    %x ", sa[6]);
  LOG_INFO ("\n DESKey2_1 / AESKey_3 :    %x ", sa[7]);
  LOG_INFO ("\n DESKey3_0 / AESKey_4 :    %x ", sa[8]);
  LOG_INFO ("\n DESKey3_1 / AESKey_5 :    %x ", sa[9]);
  LOG_INFO ("\n AESKey_6 :    %x ", sa[10]);
  LOG_INFO ("\n AESKey_7 :    %x ", sa[11]);

  LOG_INFO ("\n");

  LOG_INFO ("\n InnerDigest_0 (A) / XCBCMACKey1_0 / HashKey_0 :    %x ",
            sa[12]);
  LOG_INFO ("\n InnerDigest_1 (B) / XCBCMACKey1_1 / HashKey_1 :    %x ",
            sa[13]);
  LOG_INFO ("\n InnerDigest_2 (C) / XCBCMACKey1_2 / HashKey_2 :    %x ",
            sa[14]);
  LOG_INFO ("\n InnerDigest_3 (D) / XCBCMACKey1_3 / HashKey_3 :    %x ",
            sa[15]);
  LOG_INFO ("\n InnerDigest_4 (E) / XCBCMACKey2_0 :    %x ", sa[16]);

  LOG_INFO ("\n InnerDigest_5 (F) / XCBCMACKey2_1 :    %x ", sa[17]);
  LOG_INFO ("\n InnerDigest_6 (G) / XCBCMACKey2_2 :    %x ", sa[18]);
  LOG_INFO ("\n InnerDigest_7 (H) / XCBCMACKey2_3 :    %x ", sa[19]);
  LOG_INFO ("\n InnerDigest_8 (I) :    %x ", sa[20]);
  LOG_INFO ("\n InnerDigest_9 (J) :    %x ", sa[21]);
  LOG_INFO ("\n InnerDigest_10 (K) :    %x ", sa[22]);
  LOG_INFO ("\n InnerDigest_11 (L) : %x \n", sa[23]);
  LOG_INFO ("\n InnerDigest_12 (M) : %x ", sa[24]);
  LOG_INFO ("\n InnerDigest_13 (N) : %x ", sa[25]);
  LOG_INFO ("\n InnerDigest_14 (O) : %x ", sa[26]);
  LOG_INFO ("\n InnerDigest_15 (P) : %x \n", sa[27]);

  LOG_INFO ("\n");

  LOG_INFO ("\n OuterDigest0 (A) / XCBCMACKey3_0  : %x \n", sa[28]);
  LOG_INFO ("\n OuterDigest1 (B) / XCBCMACKey3_1  : %x \n", sa[29]);
  LOG_INFO ("\n OuterDigest2 (C) / XCBCMACKey3_2  : %x \n", sa[30]);
  LOG_INFO ("\n OuterDigest3 (D) / XCBCMACKey3_3  : %x \n", sa[31]);

  LOG_INFO ("\n OuterDigest4 (E)   : %x ", sa[32]);
  LOG_INFO ("\n OuterDigest5 (F)   : %x ", sa[33]);
  LOG_INFO ("\n OuterDigest6 (G)   : %x ", sa[34]);
  LOG_INFO ("\n OuterDigest7 (H)   : %x ", sa[35]);
  LOG_INFO ("\n OuterDigest8 (I)   : %x ", sa[36]);
  LOG_INFO ("\n OuterDigest9 (J)   : %x ", sa[37]);
  LOG_INFO ("\n OuterDigest10 (K)  : %x ", sa[38]);
  LOG_INFO ("\n OuterDigest11 (L)  : %x ", sa[39]);
  LOG_INFO ("\n OuterDigest12 (M)  : %x ", sa[40]);
  LOG_INFO ("\n OuterDigest13 (N)  : %x ", sa[41]);
  LOG_INFO ("\n OuterDigest14 (O)  : %x ", sa[42]);
  LOG_INFO ("\n OuterDigest15 (P)  : %x ", sa[43]);

  LOG_INFO ("\n\n SPI  : %x \n", sa[44]);

  LOG_INFO ("\n SeqNum_0  : %x ", sa[45]);
  LOG_INFO ("\n SeqNum_1  : %x ", sa[46]);

  LOG_INFO ("\n SeqNumMask_0_0  : %x ", sa[47]);
  LOG_INFO ("\n SeqNumMask_0_1  : %x ", sa[48]);
  LOG_INFO ("\n SeqNumMask_0_2  : %x ", sa[49]);
  LOG_INFO ("\n SeqNumMask_0_3  : %x ", sa[50]);

  LOG_INFO ("\n\n IV_0 / NONCE / SALT : %x ", sa[51]);
  LOG_INFO ("\n IV_1 : %x ", sa[52]);
  LOG_INFO ("\n IV_2 : %x ", sa[53]);
  LOG_INFO ("\n IV_3 : %x ", sa[54]);

  LOG_INFO ("\n\n StatePntr : %x \n", sa[55]);

  LOG_INFO ("\n ARC4ijPntr[15:0] : %x ", sa[56] & 0xffff);
  LOG_INFO ("\n\n ARC4_StatePntr : %x \n", sa[57]);

  LOG_INFO ("\n } :<- ENDS SA Rev2 ------------------------------------- \n");

}


void
slad_test_print_sa_dynamic (void *sa_dynamic)
{
  UINT32 *sa;
  int offset, i;
  unsigned int KeySize, InnerDigestSize, OuterDigestSize;
  sa = (UINT32 *) sa_dynamic;

  LOG_INFO
    ("\n { ->: Dynamic SA  ------------------------------------------ \n");

  LOG_INFO ("\n Contents : %x ", sa[0]);
  LOG_INFO ("\n Contents in bits : \n");
  slad_test_print_word_in_bits (sa[0]);


  LOG_INFO ("\n Command_0 : %x ", sa[1]);

  LOG_INFO ("\n Command_0 in bits : \n");
  slad_test_print_word_in_bits (sa[1]);
  slad_test_print_decode_sa_command0 (sa[1]);

  LOG_INFO ("\n Command_1 : %x ", sa[2]);

  LOG_INFO ("\n Command_1 in bits : \n");
  slad_test_print_word_in_bits (sa[2]);
  slad_test_print_decode_sa_command1 (sa[2]);

  KeySize = (sa[0] >> 4) & 0xf;
  InnerDigestSize = (sa[0] >> 8) & 0x1f;
  OuterDigestSize = (sa[0] >> 13) & 0x1f;

  for (i = 0, offset = 3; i < KeySize; i++, offset++)
    {
      LOG_INFO ("\n Key[%d] : %x ", i, sa[offset]);
    }
  LOG_INFO ("\n");

  for (i = 0; i < InnerDigestSize; i++, offset++)
    {
      LOG_INFO ("\n InnerDigest[%d] : %x ", i, sa[offset]);
    }

  LOG_INFO ("\n");

  for (i = 0; i < OuterDigestSize; i++, offset++)
    {
      LOG_INFO ("\n OuterDigest[%d] : %x ", i, sa[offset]);
    }
  LOG_INFO ("\n");

  if ((sa[0] >> 18) & 0x1)
    {
      LOG_INFO ("\n SPI : %x \n", sa[offset]);
      offset++;
    }

  if ((sa[0] >> 19) & 0x1)
    {
      LOG_INFO ("\n SeqNum0 : %x \n", sa[offset]);
      offset++;
    }

  if ((sa[0] >> 20) & 0x1)
    {
      LOG_INFO ("\n SeqNum1 : %x \n", sa[offset]);
      offset++;
    }

  if ((sa[0] >> 21) & 0x1)
    {
      LOG_INFO ("\n SeqNumMask0 : %x \n", sa[offset]);
      offset++;
    }

  if ((sa[0] >> 22) & 0x1)
    {
      LOG_INFO ("\n SeqNumMask1 : %x \n", sa[offset]);
      offset++;
    }

  if ((sa[0] >> 23) & 0x1)
    {
      LOG_INFO ("\n SeqNumMask2 : %x \n", sa[offset]);
      offset++;
    }

  if ((sa[0] >> 24) & 0x1)
    {
      LOG_INFO ("\n SeqNumMask3 : %x \n", sa[offset]);
      offset++;
    }

  if ((sa[0] >> 25) & 0x1)
    {
      LOG_INFO ("\n IV0 / NONCE / SALT : %x \n ", sa[offset]);
      offset++;
    }
  if ((sa[0] >> 26) & 0x1)
    {
      LOG_INFO ("\n IV1 : %x \n", sa[offset]);
      offset++;
    }
  if ((sa[0] >> 27) & 0x1)
    {
      LOG_INFO ("\n IV2 : %x \n", sa[offset]);
      offset++;
    }
  if ((sa[0] >> 28) & 0x1)
    {
      LOG_INFO ("\n IV3 : %x \n", sa[offset]);
      offset++;
    }
  if ((sa[0] >> 29) & 0x1)
    {
      LOG_INFO ("\n StatePntr : %x \n", sa[offset]);
      offset++;
    }
  if ((sa[0] >> 30) & 0x1)
    {
      LOG_INFO ("\n ARC4ijPntr : %x \n", sa[offset] & 0xffff);
      offset++;
    }
  if ((sa[0] >> 31) & 0x1)
    {
      LOG_INFO ("\n ARC4StatePntr : %x \n", sa[offset] & 0xffff);
      offset++;
    }

  LOG_INFO
    ("\n } :<- ENDS Dynamic SA  ------------------------------------- \n");

}





void
slad_test_print_srec_rev2 (void *srec_rev2)
{
  UINT32 *srec;
  srec = (UINT32 *) srec_rev2;

  LOG_INFO
    ("\n { ->:  State Record Rev 2 ---------------------------------\n");

  LOG_INFO ("\n SaveIV_0 : %x ", srec[0]);
  LOG_INFO ("\n SaveIV_1 : %x ", srec[1]);
  LOG_INFO ("\n SaveIV_2 : %x ", srec[2]);
  LOG_INFO ("\n SaveIV_3 : %x ", srec[3]);

  LOG_INFO ("\n\n SaveHashByteCntr0 : %x ", srec[4]);
  LOG_INFO ("\n SaveHashByteCntr1 : %x \n", srec[5]);

  LOG_INFO ("\n  SaveDigest_0 (A) / SaveXBCMACDigest_0 : %x ", srec[6]);
  LOG_INFO ("\n  SaveDigest_1 (B) / SaveXBCMACDigest_1 : %x ", srec[7]);
  LOG_INFO ("\n  SaveDigest_2 (C)/ SaveXBCMACDigest_2 : %x ", srec[8]);
  LOG_INFO ("\n  SaveDigest_3 (D) / SaveXBCMACDigest_3 : %x \n", srec[9]);

  LOG_INFO ("\n  SaveDigest _4 (E) : %x ", srec[10]);
  LOG_INFO ("\n  SaveDigest _5 (E) : %x ", srec[11]);
  LOG_INFO ("\n  SaveDigest _6 (E) : %x ", srec[12]);
  LOG_INFO ("\n  SaveDigest _7 (E) : %x ", srec[13]);
  LOG_INFO ("\n  SaveDigest _8 (E) : %x ", srec[14]);
  LOG_INFO ("\n  SaveDigest _9 (E) : %x ", srec[15]);
  LOG_INFO ("\n  SaveDigest _10 (E) : %x ", srec[16]);
  LOG_INFO ("\n  SaveDigest _11 (E) : %x ", srec[17]);
  LOG_INFO ("\n  SaveDigest _12 (E) : %x ", srec[18]);
  LOG_INFO ("\n  SaveDigest _13 (E) : %x ", srec[19]);
  LOG_INFO ("\n  SaveDigest _14 (E) : %x ", srec[20]);
  LOG_INFO ("\n  SaveDigest _15 (E) : %x ", srec[21]);

  LOG_INFO
    ("\n } :<-  ENDS State Record Rev 2 ----------------------------\n");

}

#ifndef  SIZE_OF_REV1_SA_IN_WORDS

#define  SIZE_OF_REV1_SA_IN_WORDS   32
#define  SIZE_OF_REV1_SREC_IN_WORDS    10
#define  SIZE_OF_REV2_SA_IN_WORDS    58
#define  SIZE_OF_REV2_SREC_IN_WORDS    22
#define  MAX_SIZE_OF_DYNAMIC_SA      59
#define INVALID_SA_REVISION -1
#define REVISION1_SA 1
#define REVISION2_SA 2
#define DYNAMIC_SA   10

#define REVISION1_SREC 1
#define REVISION2_SREC 2
#define REVISON_ARC4   10

#define SIZE_OF_DYNAMIC_SA_SREC_IN_WORDS 22
#define SIZE_OF_ARC4_SREC_IN_WORDS     64

#define SIZE_OF_REV1_SA_IN_WORDS    32
#define SIZE_OF_REV1_SREC_IN_WORDS    10

#define SIZE_OF_REV2_SA_IN_WORDS    58
#define SIZE_OF_REV2_SREC_IN_WORDS    22

#define MAX_SIZE_OF_DYNAMIC_SA      59


#endif


void
slad_test_print_sa (void *sa, int size_in_words)
{
  int sa_rev;

  if (size_in_words == SIZE_OF_REV1_SA_IN_WORDS)
    sa_rev = REVISION1_SA;
  else if (size_in_words == SIZE_OF_REV2_SA_IN_WORDS)
    sa_rev = REVISION2_SA;
  else if (size_in_words <= MAX_SIZE_OF_DYNAMIC_SA)
    sa_rev = DYNAMIC_SA;
  else
    sa_rev = 0;

  switch (sa_rev)
    {
    case REVISION1_SA:
      slad_test_print_sa_rev1 (sa);
      break;

    case REVISION2_SA:
      slad_test_print_sa_rev2 (sa);
      break;

    case DYNAMIC_SA:
      slad_test_print_sa_dynamic (sa);
      break;

    default:
      LOG_INFO ("\n Invalid SA Revision, can't print SA. \n");

    }
}

void
slad_test_print_arc4_state_record (void *arc4_srec)
{
  UINT32 *arc4;
  int i;

  arc4 = arc4_srec;

  LOG_INFO ("\n{ ->:  ARC4 State Record -------------------------- \n");

  for (i = 0; i < 64; i++)
    {
      if ((i % 4) == 0)
        {
          LOG_INFO ("\n");
          LOG_INFO ("%-3d to %-3d :  \t", i, i + 3);
        }
      LOG_INFO ("%08x\t", arc4[i]);

    }
  LOG_INFO ("\n");

  LOG_INFO ("\n} :<- ENDS ARC4 State Record ---------------------- \n");

}

void
slad_test_print_srec (void *srec, int size_in_words)
{
  int srec_rev;

  if (size_in_words == SIZE_OF_REV1_SREC_IN_WORDS)
    srec_rev = REVISION1_SREC;
  else if (size_in_words == SIZE_OF_REV2_SREC_IN_WORDS)
    srec_rev = REVISION2_SREC;
  else if (size_in_words == SIZE_OF_ARC4_SREC_IN_WORDS)
    srec_rev = REVISON_ARC4;
  else
    srec_rev = 0;


  switch (srec_rev)
    {
    case REVISION1_SREC:
      slad_test_print_srec_rev1 (srec);
      break;
    case REVISION2_SREC:
      slad_test_print_srec_rev2 (srec);
      break;

    case REVISON_ARC4:
      slad_test_print_arc4_state_record (srec);
      break;
    default:
      LOG_INFO
        ("\n Invalid State Record Revision; can't print State Record \n");
      LOG_INFO ("\n Size of State Record in words : %d \n", size_in_words);

    }
}

void
slad_test_print_decode_register_pe_control_status (UINT32 cs)
{
  LOG_INFO ("\n{ ->: Decoding PE Control / Status  Register ----------\n");
  LOG_INFO ("\n In Bits : \n");

  slad_test_print_word_in_bits (cs);

  if (cs & 0x1)
    LOG_INFO ("\n Host Ready : 1 : Host has populated the descriptor \n");
  else
    LOG_INFO ("\n Host Ready : 0 : Host has NOT populated the descriptor \n");

  if ((cs >> 1) & 0x1)
    LOG_INFO
      ("\n PE Done : 1 : PE has finished processing the descriptor \n");
  else
    LOG_INFO ("\n PE Done : 0 : PE has NOT yet processed the descriptor \n");

  if ((cs >> 3) & 0x1)
    LOG_INFO
 ("\n Init ARC4 : 1 : For ARC4 Stateful mode,continuefrom prevalgostate \n");
  else
    LOG_INFO
("\n Init ARC4:0:ForARC4,read key from SA and init S-boxes with this key \n");

  if ((cs >> 4) & 0x1)
    LOG_INFO ("\n Hash Final : 1 : Generate final hash \n");
  else
    LOG_INFO ("\n Hash Final : 0 : Generate intermediate hash \n");

  if ((cs >> 5) & 0x1)
    LOG_INFO ("\n Use Cached SA : Yes : Use SA cached inside PE \n");
  else
    LOG_INFO ("\n Use Cache SA : No : Use fresh SA \n");

  LOG_INFO ("\n Next Header / Pad Value : %d \n", (cs >> 8) & 0xff);
  LOG_INFO ("\n Status : 0x%x \n", (cs >> 16) & 0xff);



  LOG_INFO ("\n} <-: DONE - Decoding PE Control / Status  Register ---");




}

static void
calculate_srec_offset (void *sa_ptr, int *srec_offset, int *arc4_srec_offset)
{

  int i, offset = 1;
  unsigned int sa_contents;
  sa_contents = ((unsigned int *) sa_ptr)[0];

  // Size of Commands
  offset += (sa_contents & 0xf);
  // KeySize
  offset += ((sa_contents & 0xf0) >> 4);
  // Inner Digest Size
  offset += ((sa_contents & 0x1f00) >> 8);
  // Outer Digest Size
  offset += ((sa_contents & 0x3e000) >> 13);
  sa_contents >>= 18;

  for (i = 18; i <= 31; i++)
    {
      if (sa_contents & 0x1)
        {
          if (i == 29)          //  State Ptr
            {
              *srec_offset = offset;
              //offset++ ; // for reserved 64-bit addressing field
              // According to eip manual, offset should be incremented here
              // because of reserved field, but vp files do not provide
              // zeroes here, so do not increment offset.

            }
          if (i == 31)          //  ARC4 State Ptr
            {
              *arc4_srec_offset = offset;
              //offset++ ; // // for reserved 64-bit addressing field

            }
          offset++;
        }

      sa_contents >>= 1;
    }

}

void
slad_test_get_srec_offset (void *sa, int sa_size_in_words,
                           int *srec_offset_in_words,
                           int *arc4_offset_in_words)
{
  if (sa_size_in_words == SIZE_OF_REV1_SA_IN_WORDS)
    {
      *srec_offset_in_words = 27;
      *arc4_offset_in_words = 29;
    }
  else if (sa_size_in_words == SIZE_OF_REV2_SA_IN_WORDS)
    {
      *srec_offset_in_words = 55;
      *arc4_offset_in_words = 57;

    }
  else
    calculate_srec_offset (sa, srec_offset_in_words, arc4_offset_in_words);
}

void
slad_test_zeroize_srec_pointers (void *sa, int sa_size_in_words)
{
  int srec_offset_in_words=0, arc4_offset_in_words=0;

  if (sa && sa_size_in_words)
    {
      slad_test_get_srec_offset (sa, sa_size_in_words, &srec_offset_in_words,
                                 &arc4_offset_in_words);

      ((UINT32 *) sa)[srec_offset_in_words] = 0;
      ((UINT32 *) sa)[arc4_offset_in_words] = 0;
    }

}
#endif
