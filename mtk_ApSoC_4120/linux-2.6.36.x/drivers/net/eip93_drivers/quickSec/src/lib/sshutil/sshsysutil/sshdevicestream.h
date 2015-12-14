/*

sshdevicestream.h

Author: Tatu Ylonen <ylo@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
                   All rights reserved

Generic interface for opening a data stream to/from a device (hardware
device or pseudo-device).

*/

#ifndef SSHDEVICESTREAM_H
#define SSHDEVICESTREAM_H

#include "sshstream.h"

/* Opens a stream for the device specified by the given name.  Returns NULL
   on failure. */
SshStream ssh_device_open(const char *name);

#endif /* SSHDEVICESTREAM_H */
