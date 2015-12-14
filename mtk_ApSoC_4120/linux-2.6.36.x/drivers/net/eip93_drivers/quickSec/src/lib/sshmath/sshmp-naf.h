/*

  sshmp-naf.h

  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All rights reserved.

  Created Wed Mar  8 22:33:06 2000.

  */

#ifndef SSHMP_NAF_H
#define SSHMP_NAF_H

/* Routines to compute NAFs (Non-adjacent forms), and
   other representations of integer "exponents". */

/* The Morain-Olivos signed digit {-1,0,1} NAF. */
unsigned int ssh_mprz_transform_mo(SshMPIntegerConst k,
                                   char **transform_table);

/* Standard binary expansion. */
unsigned int ssh_mprz_transform_binary(SshMPIntegerConst k,
                                       char **transform_table);

/* KMOV NAF-expansions. */
unsigned int ssh_mprz_transform_kmov(SshMPIntegerConst k,
                                     char **transform_table);


#endif /* SSHMP_NAF_H */
