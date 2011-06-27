#!/bin/bash
#
# Copyright (c) 2011, Joyent Inc., All rights reserved.
#

for dir in seabios vgabios kvm/test; do
    cp roms/${dir}/config.mak.tmpl roms/${dir}/config.mak
done

echo "==> Running configure"
./configure \
    --prefix=. \
    --audio-card-list= \
    --audio-drv-list= \
    --disable-bluez \
    --disable-brlapi \
    --disable-curl \
    --enable-debug \
    --enable-kvm \
    --enable-kvm-pit \
    --disable-kvm-device-assignment \
    --disable-sdl \
    --disable-vnc-jpeg \
    --disable-vnc-png \
    --disable-vnc-sasl \
    --disable-vnc-tls \
    --kerneldir=$(cd `pwd`/../kvm; pwd) \
    --cpu=x86_64

if [[ $? != 0 ]]; then
	echo "Failed to configure, bailing"
	exit 1
fi

echo "==> Make"
gmake -j10
