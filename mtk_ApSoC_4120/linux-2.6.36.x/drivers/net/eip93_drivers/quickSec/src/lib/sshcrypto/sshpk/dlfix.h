/*

  dlfix.h

  Copyright:
        Copyright (c) 2002, 2003 SFNT Finland Oy.
	All rights reserved.

  Discrete logarithm predefined groups.

*/

#ifndef DLFIX_H
#define DLFIX_H

/* Search a parameter set of name "name". Returns TRUE if found. */
Boolean ssh_dlp_set_param(const char *name, const char **outname,
                          SshMPInteger p, SshMPInteger q, SshMPInteger g);


Boolean ssh_dlp_is_predefined_group(SshMPInteger p, SshMPInteger q,
                                    SshMPInteger g);

#endif /* DLFIX_H */
