#!/bin/bash
#
# Copyright (c) 2019, Joyent, Inc.
#

for dir in seabios vgabios kvm/test; do
	[[ ! -f roms/${dir}/config.mak.tmpl ]] || \
	    cp roms/${dir}/config.mak.tmpl roms/${dir}/config.mak
done

PNGDIR="${PWD}/libpng-1.5.4"
PNGINC="${PNGDIR}/proto/usr/local/include"
PNGLIB="${PNGDIR}/proto/usr/local/lib"

. $(pwd)/../../../build.env

#
# Skip dangerous GCC options (not that any specific problems are known of here).
#
if [[ "$PRIMARY_COMPILER_VER" -gt 4 ]]; then
	XCFLAGS=-fno-aggressive-loop-optimizations
fi

if [[ ! -d ${PNGDIR} ]]; then
	(curl -k https://download.joyent.com/pub/kvm-cmd/libpng-1.5.4.tar.gz | \
	    gtar -zxf -)
	if [[ $? != "0" || ! -d ${PNGDIR} ]]; then
		echo "Failed to get libpng."
		rm -rf ${PNGDIR}
		exit 1
	fi
fi

if [[ ! -e ${PNGLIB}/libpng.a ]]; then
	(cd ${PNGDIR} && \
	    CC="${CC:-${STRAP_AREA}/usr/bin/gcc}" \
	    LDFLAGS="-m64 -L${DESTDIR}/usr/lib/amd64 -L${DESTDIR}/lib/amd64" \
	    CPPFLAGS="-isystem ${DESTDIR}/usr/include" \
	    CFLAGS="-m64 $XCFLAGS" ./configure --disable-shared && \
	    make && \
	    mkdir -p ${PNGDIR}/proto && \
	    make DESTDIR=${PNGDIR}/proto install)
fi

echo "==> Running configure"
KVM_DIR="${KVM_DIR:-$(cd `pwd`/../kvm; pwd)}"
CC="${CC:-${STRAP_AREA}/usr/bin/gcc}"
XCFLAGS="$XCFLAGS -fno-builtin -I${PNGINC} -isystem ${DESTDIR}/usr/include -msave-args"
XLDFLAGS="-nodefaultlibs -L${PNGLIB} -L${DESTDIR}/usr/lib/amd64 -L${DESTDIR}/lib/amd64"
XLDFLAGS="${XLDFLAGS} -Wl,-zfatal-warnings -Wl,-zassert-deflib"
XLDFLAGS="${XLDFLAGS} -lz -lm -lc -lvnd"
./configure \
    --cc=$CC \
    --extra-cflags="${XCFLAGS}" \
    --extra-ldflags="${XLDFLAGS}" \
    --prefix=/smartdc \
    --audio-card-list= \
    --audio-drv-list= \
    --disable-bluez \
    --disable-brlapi \
    --disable-curl \
    --enable-debug \
    --disable-docs \
    --enable-kvm \
    --enable-kvm-pit \
    --enable-vnc-png \
    --disable-kvm-device-assignment \
    --disable-sdl \
    --disable-vnc-jpeg \
    --disable-vnc-sasl \
    --disable-vnc-tls \
    --enable-trace-backend=dtrace \
    --kerneldir="$KVM_DIR" \
    --cpu=x86_64

if [[ $? != 0 ]]; then
	echo "Failed to configure, bailing"
	exit 1
fi


#
# Make sure ctf utilities are in our path
#
KERNEL_SOURCE="${KERNEL_SOURCE:-$(pwd)/../../illumos}"
CTFBINDIR="$KERNEL_SOURCE"/usr/src/tools/proto/root_i386-nd/opt/onbld/bin/i386
export PATH="$PATH:$CTFBINDIR"

if [[ -z "$CONFIGURE_ONLY" ]]; then
	echo "==> Make"
	V=1 gmake
else
	echo "Not running make per-request"
fi
