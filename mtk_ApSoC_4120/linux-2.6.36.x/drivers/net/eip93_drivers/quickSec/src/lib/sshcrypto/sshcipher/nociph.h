/*

  nociph.h

  Copyright:
        Copyright (c) 2002, 2003 SFNT Finland Oy.
	All rights reserved.

  Cipher 'none'.

*/

#ifndef NOCIPH_H
#define NOCIPH_H

SshCryptoStatus
ssh_none_cipher(void *context, unsigned char *dest,
		const unsigned char *src, size_t len,
		unsigned char *iv);

#endif /* NOCIPH_H */
