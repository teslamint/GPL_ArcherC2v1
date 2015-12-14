#include <stdio.h>
#include "sshincludes.h"

#include "ssheap.h"

#define SSH_DEBUG_MODULE "SshTEapFiles"

/* Test code for supporting EAP AKA and EAP SIM keys
   reading from a file. This is really ugly code, since
   this is testing code. So do not read this file unless
   you are ready face some ugly code. The code is also 
   almost error chceking free, so core's are expected. */

#ifdef SSHDIST_EAP_AKA
/* Return the length of copied bytes. -1 on error. */
int copy_aka_keys(unsigned char *line, unsigned char *ret, int len)
{
  /* Temporary variables for reading the variables. */
  unsigned char tmp1[32] = "";
  unsigned char tmp2[32] = "";
  unsigned char tmp3[32] = "";
  unsigned char tmp4[32] = "";
  unsigned char tmp5[128] = "";
  int i;

  sscanf(line, "%32c,%32c,%32c,%32c,%32c", tmp1, tmp2, tmp3, tmp4, tmp5);

  for (i = 0; i < 32; i++)
    {
      if (!isxdigit(tmp2[i]) || !isxdigit(tmp3[i]) || 
          !isxdigit(tmp4[i]))
        return -1;
    }

  for (i = 0; i < 32; i++)
    {
      /* Wipe out everything that does not seem to belong to the 
         RES value. */
      if (!isxdigit(tmp5[i]))
        tmp5[i] = 0x0;
    }

  /* If the RES value is not dividable by 2 or its too short or
     too long, forget copying. */
  if (strlen(tmp5) % 2 || strlen(tmp5) > 32 || strlen(tmp5) < 8)
    return -1;

  /* Just error checking we have enough output buffer. 
     3 * 16 is the base attributes, 1 + tmp5_len is 
     the res length. */
  if (len < ((3 * 16) + strlen(tmp5) + 1))
    return -1;

  /* Make the output. */
  for (i = 0; i < 16; i++)
    {
      int s;

      sscanf(&tmp2[i * 2], "%02x", &s);
      ret[i] = s & 0xff;
      sscanf(&tmp3[i * 2], "%02x", &s);
      ret[i + 16] = s & 0xff;
      sscanf(&tmp4[i * 2], "%02x", &s);
      ret[i + 32] = s & 0xff;
    }

  /* Put the length for res as defined in ssheap.h */
  ret[48] = (strlen(tmp5) * 4) & 0xff;

  /* And put also the RES value to the data. */
  for (i = 0; i < (strlen(tmp5) / 2); i++)
    {
      int s;
      
      sscanf(&tmp5[i * 2], "%02x", &s);
      ret[i + 49] = s & 0xff;
    }

  /* Base length 48B + 1 + length of res. See ssheap.h. */
  return 48 + 1 + (strlen(tmp5) / 2);
}
#endif /* SSHDIST_EAP_AKA */

#ifdef SSHDIST_EAP_SIM
/* Return the length of copied bytes. -1 on error. */
int copy_sim_keys(unsigned char *line, unsigned char *ret, int len)
{
  /* Temporary variables for reading the variables. */
  unsigned char tmp[128] = "";
  unsigned char tmp1[128] = "";
  unsigned char tmp2[128] = "";
  int i;

  sscanf(line, "%32c,%8c,%16c", tmp, tmp1, tmp2);

  /* Check SRES value. */
  for (i = 0; i < 8; i++)
    {
      if (!isxdigit(tmp1[i]))
        return -1;
    }

  /* Check Kc value. */
  for (i = 0; i < 16; i++)
    {
      if (!isxdigit(tmp2[i]))
        return -1;
    }
  
  /* Make the output. */
  for (i = 0; i < 4; i++)
    {
      int s;

      sscanf(&tmp1[i * 2], "%02x", &s);
      ret[i] = s & 0xff;
    }

  for (i = 0; i < 8; i++)
    {
      int s;

      sscanf(&tmp2[i * 2], "%02x", &s);
      ret[i + 4] = s & 0xff;
    }

  /* The length is 12, see ssheap.h for more details. */
  return 12;
}
#endif /* SSHDIST_EAP_SIM */

#ifdef SSHDIST_EAP_AKA
/* One line of the the aka_keys.dat file is in following format (the values
   are always separated with "," ):
   32 chars of hex representation of rand, 32 chars of hex representation
   of autn key, 32 chars of hex representation of Ik, 32 chars of hex 
   representation of Ck, and from 8 to 32 (must be dividable by 2) hex chars
   of Res value.

   Example 1:
   a1a2a3a4a5a6a7a8a9a0a1a2a3a4a5a6,b1b2b3b4b5b6b7b8b9b0b1b2b3b4b5b6,c1c2c3...
...c4c5c6c7c8c9c0c1c2c3c4c5c6,d1d2d3d4d5d6d7d8d9d0d1d2d3d4d5d6,e1e2e3e4

   Example 2:
   a1a2a3a4a5a6a7a8a9a0a1a2a3a4a5a6,b1b2b3b4b5b6b7b8b9b0b1b2b3b4b5b6,c1c2c3...
...c4c5c6c7c8c9c0c1c2c3c4c5c6,d1d2d3d4d5d6d7d8d9d0d1d2d3d4d5d6,e1e2e3e4e5e6e7..
...e8e9e0e1e2e3e4e5e6
*/
static int
eap_get_aka_information(int type, const unsigned char *input, int input_len,
                        unsigned char *ret, int ret_len)
{
  unsigned char line[1024]   = "";
  unsigned char lin_rand[33] = "";
  char         *file_read    = NULL;
  int           i            = 0;
  int           rval         = 0;
  FILE *f;

  /* Input just has to be 32B. See ssheap.h for more details. 
     Output buffer has to be also lengthy enough. */
  if (input_len != 32 || ret_len < ((4 * 16) + 1))
    return -1;

  for (i = 0; i < 16; i++)
    {
      ssh_snprintf(&lin_rand[i * 2], sizeof(lin_rand), "%02x", 
                   input[i] & 0xff);
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Checking for key match for rand %s", lin_rand));

  if (type == SSH_EAP_TYPE_AKA)
    {
      if (!(f = fopen("./aka_keys.dat", "r")))
        return -1;
    }
#ifdef SSHDIST_EAP_AKA_DASH
  if (type == SSH_EAP_TYPE_AKA_DASH)
    {
      if (!(f = fopen("./akadash_keys.dat", "r")))
        return -1;
    }
#endif /* SSHDIST_EAP_AKA_DASH */

  /* Find the line */
  for (file_read = fgets(line, sizeof(line), f); file_read; 
       file_read = fgets(line, sizeof(line), f))
    {
      if (!memcmp(file_read, lin_rand, 32))
        {

          rval = copy_aka_keys(line, ret, ret_len);
          if (rval < 0)
            {
              fclose(f);
              return -1;
            }

          /* AUTN VALUE check. If it differs, the AUTN is used 
             as AUTS in return. We do not have anyway to simulate 
             the AUTS correctly, so it's all the same to use 
             AUTN in AUTS. */
          SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("Comp 1"), &input[16], 16);
          SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("Comp 2"), ret, 16);
          if (memcmp(&input[16], ret, 16)) 
            {
              /* The AUTS value is already in the head of the
                 buffer. Just return the length. */
              fclose(f);
              return 16;
            }
          else
            {
              SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("Successful return"),
                                ret + 16, rval - 16);
              /* Copy the AUTS out of the return value 
                 and return the succesful data. */
              memcpy(ret, &ret[16], rval - 16);
              fclose(f);
              return rval - 16;
            }
        }
    }

  fclose(f);
  return -1;
}
#endif /* SSHDIST_EAP_AKA */


#ifdef SSHDIST_EAP_SIM
/* One line of the the sim_keys.dat file is in following format (the values
   are always separated with "," ):
   32 chars of hex representation of rand, 8 chars of hex representation
   of sres key, 16 chars of hex representation of Kc.

   Example:
   a1a2a3a4a5a6a7a8a9a0a1a2a3a4a5a6,b1b2b3b4,c1c2c3c4c5c6c7c8
*/

static int
eap_get_sim_information(const unsigned char *input, int input_len,
                        unsigned char *ret, int ret_len)
{
  unsigned char line[1024]   = "";
  unsigned char lin_rand[33] = "";
  char         *file_read    = NULL;
  int           i            = 0;
  int           copy_cnt     = 0;
  FILE *f;

  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("reading sim information given rand's"), 
                    input, input_len);
  /* Checking of the input. See ssheap.h for more details. */
  if ((input_len / 16) != 3 &&
      (input_len / 16) != 2)
    return -1;

  /* Check the ret buffer length. This is testing
     code and that's why these quite odd calculation
     instead of nicer defines. */
  if (ret_len < ((input_len / 16) * 12))
    return -1;
  
  for (i = 0; i < 16; i++)
    {
      ssh_snprintf(&lin_rand[i * 2], sizeof(lin_rand), "%02x", 
                   input[i] & 0xff);
    }

  SSH_DEBUG(SSH_D_LOWOK, ("linearized rand: %s", lin_rand));

  if (!(f = fopen("./sim_keys.dat", "r"))) 
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Could not open sim_keys.dat"));
      return -1;
    }

  /* Find the line */
  for (file_read = fgets(line, sizeof(line), f); file_read; 
       file_read = fgets(line, sizeof(line), f))
    {
      SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("Comparing 1"), file_read, 32);
      SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("Comparing 2"), lin_rand, 32);
      if (!memcmp(file_read, lin_rand, 32))
        {
          if (copy_sim_keys(line, &ret[copy_cnt * 12], 
                            ret_len - (copy_cnt * 12)) < 0)
            {
              SSH_DEBUG(SSH_D_LOWOK ,("sim information copying failed"));
              fclose(f);
              return -1;
            }

          copy_cnt++;
          
          if (copy_cnt == (input_len / 16))
            {
              return (copy_cnt * 12);
            }

          /* Take the next rand. */
          for (i = 0; i < 16; i++)
            {
              ssh_snprintf(&lin_rand[i * 2], sizeof(lin_rand), "%02x", 
                           input[i + (copy_cnt * 16)] & 0xff);
            }

          SSH_DEBUG(SSH_D_LOWOK, ("copied key, new linearized rand: %s", 
                                  lin_rand));
        }
    }
  

  SSH_DEBUG(SSH_D_FAIL, ("Did not find enough RAND's"));
  fclose(f);
  return -1;
}
#endif /* SSHDIST_EAP_SIM */

/*
  type is the EAP subtype, i.e. AKA or SIM.... 
  ret is the place to put the responses correctly 
  formatted. 
 */
int eap_read_sim_files(int type, const unsigned char *input, 
                       int input_len, unsigned char *ret, int ret_len)
{
  SSH_DEBUG(SSH_D_LOWOK, ("Requested to read type %d file", type));

  switch(type) 
    {
#ifdef SSHDIST_EAP_AKA
    case SSH_EAP_TYPE_AKA:
#ifdef SSHDIST_EAP_AKA_DASH
    case SSH_EAP_TYPE_AKA_DASH:
#endif /* SSHDIST_EAP_AKA_DASH */
      return eap_get_aka_information(type, input, input_len, ret, ret_len);
#endif /* SSHDIST_EAP_AKA */

#ifdef SSHDIST_EAP_SIM
    case SSH_EAP_TYPE_SIM:
      return eap_get_sim_information(input, input_len, ret, ret_len);
#endif /* SSHDIST_EAP_SIM */

    default:
      return -1;
    }
}

