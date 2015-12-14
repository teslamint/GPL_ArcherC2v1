#
# Environment setup script for AMCC405ex build using the "new" build system
#
EIP93_DIR=`pwd`
export PATH=/opt/buildroot-gcc342/bin:$PATH
export BUILDROOT=$EIP93_DIR

export KERNEL_VERSION=2.6.36

# This is the standard include directory of ELDK
export ELDK=/opt/buildroot-gcc342/bin

#These you should not need to touch
export ARCH=mips
export LIBC=uclibc
export TARGET=mipsel-linux-uclibc
export TOOLDIR=/opt/buildroot-gcc342/bin
export CROSS_COMPILE=$TOOLDIR/$TARGET-

export CC="$TOOLDIR/$TARGET-gcc -mips32r2 -msoft-float"
export AR=$TOOLDIR/$TARGET-ar
export LD=$TOOLDIR/$TARGET-ld
export NM=$TOOLDIR/$TARGET-nm
export RANLIB=$TOOLDIR/$TARGET-ranlib
export AS=$TOOLDIR/$TARGET-as
export KDIR=$EIP93_DIR/../../../linux-2.6.36.x
export KERN_CFLAGS="-I$KERNEL_DIR/arch/mips -DSSH_SAFENET_AMCC_SUPPORT -Os -fno-strict-aliasing -fno-common -fomit-frame-pointer"
export CFLAGS="-D_GNU_SOURCE -Os -Wno-pointer-sign -Wall -Wno-unknown-pragmas"

alias make='make ARCH=$ARCH CROSS_COMPILE=$CROSS_COMPILE -j1'
