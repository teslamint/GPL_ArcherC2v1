/*

  t-fingerprint.c

  Author: Timo J. Rinne <tri@ssh.com>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All rights reserved.

  Created Fri Apr 28 00:40:51 2000

*/

#include "sshincludes.h"
#include "sshfingerprint.h"

#define SSH_FINGERPRINT_TYPES_TESTED 6

SshFingerPrintType fp_type[SSH_FINGERPRINT_TYPES_TESTED] = {
    SSH_FINGERPRINT_BABBLE,
    SSH_FINGERPRINT_BABBLE_UPPER,
    SSH_FINGERPRINT_PGP2,
    SSH_FINGERPRINT_PGP5,
    SSH_FINGERPRINT_HEX,
    SSH_FINGERPRINT_HEX_UPPER
};

char *fp_test[] = {
  "",
  "1234567890",
  "Pineapple",
  "80bits!!"
  "96bits here!",
  "This is 128bits.",
  "160bit blob is here!",
  "192bit signature is here",
  NULL
};


char *babble_testvec[] = {
  "",
  "1234567890",
  "Pineapple",
  NULL
};

char *babble_testval[] = {
  "xexax",
  "xesef-disof-gytuf-katof-movif-baxux",
  "xigak-nyryk-humil-bosek-sonax",
  NULL
};

char *babble_testval_upper[] = {
  "XEXAX",
  "XESEF-DISOF-GYTUF-KATOF-MOVIF-BAXUX",
  "XIGAK-NYRYK-HUMIL-BOSEK-SONAX",
  NULL
};

int main()
{
  int i, j;
  char *blob;

  for (i = 0; fp_test[i] != NULL; i++)
    {
      for (j = 0; j < SSH_FINGERPRINT_TYPES_TESTED; j++)
        {
          blob = ssh_fingerprint(fp_test[i], strlen(fp_test[i]), fp_type[j]);
#if 0
          printf("FP(\"%s\", %d, \"%s\") =\n\"%s\"\n",
                 fp_test[i],
                 (int)fp_type[j],
                 ssh_fingerprint_name(fp_type[j]),
                 blob);
#else /* 0 | 1 */
          (void)ssh_fingerprint_name(fp_type[j]);
#endif /* 0 | 1 */
          ssh_xfree(blob);
        }
    }
  for (i = 0; babble_testvec[i] != NULL; i++)
    {
      blob = ssh_fingerprint(babble_testvec[i],
                             strlen(babble_testvec[i]),
                             SSH_FINGERPRINT_BABBLE);
      if (strcmp(babble_testval[i], blob) != 0)
        {
          fprintf(stderr,
                  "t-fingerprint: SSH_BABBLE(\"%s\") "
                  "returns \"%s\" while reference value is \"%s\"\n",
                  babble_testvec[i], blob, babble_testval[i]);
          exit(1);
        }
      ssh_xfree(blob);
      blob = ssh_fingerprint(babble_testvec[i],
                             strlen(babble_testvec[i]),
                             SSH_FINGERPRINT_BABBLE_UPPER);
      if (strcmp(babble_testval_upper[i], blob) != 0)
        {
          fprintf(stderr,
                  "t-fingerprint: SSH_BABBLE(\"%s\") "
                  "returns \"%s\" while reference value is \"%s\"\n",
                  babble_testvec[i], blob, babble_testval_upper[i]);
          exit(1);
        }
      ssh_xfree(blob);
    }
  ssh_util_uninit();
  exit(0);
}
