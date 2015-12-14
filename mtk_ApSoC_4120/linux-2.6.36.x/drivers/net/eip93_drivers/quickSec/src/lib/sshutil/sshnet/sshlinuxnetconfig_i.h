/*
  File: sshlinuxnetconfig_i.h

  Copyright:
        Copyright (c) 2007-2008 SFNT Finland Oy.
        All rights reserved

  Description:
        Internal header file for sshlinuxnetconfig.c and sshlinuxnetevent.c.
*/


#ifndef SSHLINUXNETCONFIG_I_H
#define SSHLINUXNETCONFIG_I_H

/** Conversion between linux interface index and SSH ifnum. */

#define SSH_LINUX_NETCONFIG_IF_INDEX_TO_IFNUM(if_index) \
  ((if_index) < 0 ? SSH_INVALID_IFNUM : (SshUInt32) (if_index))

#define SSH_LINUX_NETCONFIG_IFNUM_TO_IF_INDEX(ifnum) \
  ((ifnum) == SSH_INVALID_IFNUM ? -1 : (int) (ifnum))

#endif /* SSHLINUXNETCONFIG_I_H */
