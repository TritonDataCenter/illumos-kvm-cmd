<pre>
  ___  _____ __  __ _   _
 / _ \| ____|  \/  | | | |
| | | |  _| | |\/| | | | |
| |_| | |___| |  | | |_| |
 \__\_\_____|_|  |_|\___/
</pre>


For full documentation on all the various options for QEMU please see the html docs.


# BUILDING

Preparing:

Edit build.sh and change the --kerneldir option to point to the directory of
the kvm repository and change the --prefix option to whatever you want.

    $ ./build.sh
    $ make install


# USING

Follow the qemu documentation for all of the various options available. The
rest of this will be examples and specific pieces about how to use things with
a VNIC and a ZVOL. The following is a sample configuration for qemu running a Linux VM.

    $ /smartdc/bin/qemu-system-x86_64 \
        -enable-kvm \
        -nographic \
        -drive file=smartdc.iso,media=cdrom,if=ide \
        -boot order=cd \
        -smp 4 \
        -m 1024 \
        -vnc 0.0.0.0:0 \
        -net nic,vlan=0,name=net0,model=virtio,macaddr=90:b8:d0:c0:ff:ee\
        -net vnic,vlan=0,name=net0,ifname=eth0,macaddr=90:b8:d0:c0:ff:ee,\
             ip=10.88.88.50,netmask=255.255.255.0,gateway_ip=10.88.88.2,\
             server_ip=10.88.88.200,dns_ip0=8.8.4.4,dns_ip1=8.8.4.4,\
	     hostname=host1,lease_time=3600 \
        -no-hpet \
        -chardev socket,id=serial0,path=/tmp/vm.console,server,nowait \
        -serial chardev:serial0 \
        -drive file=/dev/zvol/rdsk/zones/rec-8,if=virtio,index=0


# ZVOLs

It is highly desirable to be able to give a virtual machine a zvol to use as a
disk. This is accomplished via the -drive option. Simply pass the block device
that corresponds to the zvol.

To create a zvol use a command similar to:

    $ zfs create -V 10g tank/vm-hdd


# VNICs

We have added an option to have a virtual machine's network interface card
directly correspond to a Crossbow vnic on the system. The -net vnic has several
mandatory arguments:

* __vlan__ must be specified and correspond to a single -net nic line
* __name__ must be specified and correspond to a single -net nic line
* __macaddr__ must be specified if the MAC Address of the VNIC does not match
  the MAC address on the -net nic line.
* __ifname__ must be specified and correspond to the name of the crossbow vnic.

To set up the crossbow vnic, simply create it. There is no need to plumb it.
The device will be opened up in promiscuous mode.

To create a vnic you'll want something akin to:

    $ dladm create-vnic -l e1000g0 vnic0

The -net vnic option also supports configuring networking on the virtual
machine via dhcp. In this mode, qemu acts as a DHCP server for the virtual
machine. To enable vnic dhcp, specify the following arguments:

* __ip__ (eg: 192.168.0.2) must be specified in order to enable dhcp
* __netmask__ (eg: 255.255.255.0) must be specified
* __gateway_ip__ (eg: 192.168.0.1) must be specified
* __server_ip__ (eg: 192.168.0.3) is optional. This allows specifying the
  IP address of qemu's DHCP server.
* __dns_ip__ (eg: 8.8.4.4) is optional, and allows specifying the DNS
  server the virtual machine will use.  The default value is 8.8.8.8.
* __dns_ip0__, __dns_ip1__, __dns_ip2__, and __dns_ip3__ are optional,
  and allow specifying a list of DNS servers, rather than just one.
  These options override the dns_ip option.
* __hostname__ (eg: myhostname) is optional. This defaults to no hostname.
* __lease_time__ (eg: 3600) is optional, and allows specifying the DHCP
  lease time in seconds.  The default value is 86400 (or 1 day).

The following is a sample -net vnic line for running with DHCP:

    -net vnic,vlan=0,name=net0,ifname=eth0,macaddr=90:b8:d0:c0:ff:ee, \
        ip=10.88.88.50,netmask=255.255.255.0,gateway_ip=10.88.88.2, \
        server_ip=10.88.88.200,dns_ip=8.8.4.4,hostname=host1,lease_time=3600

