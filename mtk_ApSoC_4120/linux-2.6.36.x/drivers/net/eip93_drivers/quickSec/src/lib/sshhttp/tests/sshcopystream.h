/*
 *
 * sshcopystream.h
 *
 * Author: Markku Rossi <mtr@ssh.fi>
 *
 *  Copyright:
 *          Copyright (c) 2002 - 2004 SFNT Finland Oy.
 *               All rights reserved.
 *
 * What is this file for?
 *
 */

#ifndef SSHCOPYSTREAM_H
#define SSHCOPYSTREAM_H

/*
 * Types and definitions.
 */

typedef void (*SshCopyStreamCopyCb)(SshBuffer to,
                                    SshBuffer from,
                                    Boolean eof_seen,
                                    void *context);

typedef void (*SshCopyStreamDestroyCb)(void *context);

/*
 * Prototypes for global functions.
 */

void ssh_copy_stream(SshStream to, SshStream from,
                     SshCopyStreamCopyCb copy,
                     SshCopyStreamDestroyCb destroy,
                     void *context);

#endif /* not SSHCOPYSTREAM_H */
