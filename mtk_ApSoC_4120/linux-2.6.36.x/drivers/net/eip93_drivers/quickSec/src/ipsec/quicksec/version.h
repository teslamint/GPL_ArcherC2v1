


# include "versioni.h"


/* See file versioni.h for the version number of the product.
   The version string MUST NOT contain whitespace, as this will
   break the distribution system */
#define SSH_IPSEC_COPYRIGHT \
  "Copyright 1997-2009 SafeNet Inc"
#define IPSEC_VERSION_STRING(_component, _version) \
  "QuickSec " _component " version " _version " library " \
  SSH_IPSEC_VERSION "\n" SSH_IPSEC_COPYRIGHT

#define SSH_IPSEC_VERSION_STRING_SHORT "QuickSec " SSH_IPSEC_VERSION
