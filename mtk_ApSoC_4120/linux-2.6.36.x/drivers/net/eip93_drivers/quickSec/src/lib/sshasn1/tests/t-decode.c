/*
  File: t-decode.c

  Description:
        Decode BER encodings from given directory. For each
        encoding print out if decoding was successful.

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
        All rights reserved.
*/

#include "sshincludes.h"
#include "sshdirectory.h"
#include "sshfileio.h"
#include "sshasn1.h"
#include "ssh_berfile.h"

int main(int ac, char **av)
{
  SshDirectoryHandle dh;

  if (ac != 2)
    return 0;

  dh = ssh_directory_open(av[1]);
  if (dh)
    {
      const char *fn;

      while (ssh_directory_read(dh))
        {
          fn = ssh_directory_file_name(dh);
          if (fn)
            {
              unsigned char *data;
              size_t len;
              char fullpath[127];

              ssh_snprintf(fullpath, sizeof(fullpath), "%s/%s", av[1], fn);
              if (ssh_read_file(fullpath, &data, &len))
                {
                  SshAsn1Context ctx;
                  SshAsn1Status status;
                  SshAsn1Tree tree;
                  SshBERFile bf;

                  if (ssh_ber_file_create(data, len, &bf)
                      == SSH_BER_FILE_ERR_OK)
                    {
                      len -= ssh_ber_file_get_free_space(bf);

                      ctx = ssh_asn1_init();
                      status = ssh_asn1_decode(ctx, data, len, &tree);
                      printf("%s: %d\n", fn, status);

                      ssh_asn1_free(ctx);
                      ssh_ber_file_destroy(bf);
                    }
                  ssh_free(data);
                }
            }
        }
      ssh_directory_close(dh);
    }
  return 0;
}
/* eof */
