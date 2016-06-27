/*
 * QEMU System Emulator
 * illumos VNIC/vnd support
 *
 * Copyright 2016 Joyent, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <assert.h>
#include <errno.h>
#include <libdlpi.h>
#include <string.h>
#include <stdio.h>
#include <stropts.h>
#include <stdlib.h>
#include <unistd.h>

#include <netpacket/packet.h>
#include <assert.h>
#include <net/if_dl.h>
#include <sys/ethernet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libvnd.h>
#include <sys/vnd.h>
#include <sys/frameio.h>

#include "net/vnic.h"
#include "net/vnic-dhcp.h"

#include "qemu-common.h"
#include "qemu-error.h"
#include "qemu-option.h"
#include "qemu-char.h"

/*
 * XXX We should determine a good way to get this buffer size. 64k feels like
 * such an arbitrary number...
 */
#define	VNIC_BUFSIZE	65536

typedef struct VNICState {
	VLANClientState	vns_nc;
	int		vns_fd;
	unsigned int	vns_rpoll;
	unsigned int	vns_wpoll;
	uint8_t		vns_buf[VNIC_BUFSIZE];
	uint8_t		vns_txbuf[VNIC_BUFSIZE];
	uint_t		vns_sap;
	vnd_handle_t	*vns_hdl;
	VNICDHCPState	vns_ds;
	frameio_t	*vns_rfio;
	frameio_t	*vns_wfio;
} VNICState;

static void vnic_update_fd_handler(VNICState *);

static void
vnic_read_poll(VNICState *vsp, int enable)
{
	vsp->vns_rpoll = enable;
	vnic_update_fd_handler(vsp);
}

static void
vnic_write_poll(VNICState *vsp, int enable)
{
	vsp->vns_wpoll = enable;
	vnic_update_fd_handler(vsp);
}

static void
vnic_poll(VLANClientState *ncp, bool enable)
{
	VNICState *vsp = DO_UPCAST(VNICState, vns_nc, ncp);
	vnic_read_poll(vsp, 1);
	vnic_write_poll(vsp, 1);
}

/*
 * Because this is a single packet API, just read(2). If QEMU's net backend were
 * better we could send more packets at once.
 */
static int
vnic_read_packet(VNICState *vsp, uint8_t *buf, int len)
{
	int ret;

	do {
		ret = read(vsp->vns_fd, buf, len);
	} while (ret == -1 && errno == EINTR);

	if (ret == -1 && errno == EAGAIN) {
		vnic_read_poll(vsp, 1);
		return (0);
	}

	return (ret);
}

/*
 * For a single packet, just use write(2).
 */
static int
vnic_write_packet(VNICState *vsp, const uint8_t *buf, int len)
{
	int ret;

	do {
		ret = write(vsp->vns_fd, buf, len);
	} while (ret == -1 && errno == EINTR);

	if (ret == -1 && errno == EAGAIN) {
		vnic_write_poll(vsp, 1);
		return (0);
	}

	return (ret);
}

static int
vnic_can_send(void *opaque)
{
	VNICState *vsp = opaque;
	return (qemu_can_send_packet(&vsp->vns_nc));
}

static void
vnic_send_completed(VLANClientState *nc, ssize_t len)
{
	VNICState *vsp = DO_UPCAST(VNICState, vns_nc, nc);
	vnic_read_poll(vsp, 1);
}

/* outside world -> VM */
static void
vnic_send(void *opaque)
{
	VNICState *vsp = opaque;
	int ret;

	do {
		ret = vnic_read_packet(vsp, vsp->vns_buf,
		    sizeof (vsp->vns_buf));
		if (ret <= 0)
			break;

		ret = qemu_send_packet_async(&vsp->vns_nc, vsp->vns_buf, ret,
		    vnic_send_completed);

		if (ret == 0)
			vnic_read_poll(vsp, 0);

	} while (ret > 0 && qemu_can_send_packet(&vsp->vns_nc));
}

static void
vnic_writable(void *opaque)
{
	VNICState *vsp = opaque;
	vnic_write_poll(vsp, 0);
	qemu_flush_queued_packets(&vsp->vns_nc);
}

/* VM -> outside world */
static ssize_t
vnic_receive(VLANClientState *ncp, const uint8_t *buf, size_t size)
{
	uint16_t ethtype;
	VNICState *vsp = DO_UPCAST(VNICState, vns_nc, ncp);

	if (vsp->vns_ds.vnds_enabled && get_ethertype(buf, size, &ethtype)) {
		VNICDHCPState *vdsp = &vsp->vns_ds;
		int ret;
		switch (ethtype) {
		case ETH_P_ARP:
			if (!is_arp_request(buf, size, vdsp))
				goto send;
			ret = create_arp_response(buf, size, vdsp);
			break;
		case ETH_P_IP:
			if (!is_dhcp_request(buf, size))
				goto send;
			ret = create_dhcp_response(buf, size, vdsp);
			break;
		default:
			goto send;
		}

		if (!ret)
			return (size);

		ret = qemu_send_packet_async(&vsp->vns_nc,
		    vdsp->vnds_buf, ret, vnic_send_completed);
		if (ret == 0)
			vnic_read_poll(vsp, 0);

		return (size);
	}

send:
	return (vnic_write_packet(vsp, buf, size));
}

static ssize_t
vnic_receive_iov(VLANClientState *ncp, const struct iovec *iov,
    int iovcnt)
{
	int ret, i;
	uint16_t ethtype;
	size_t total, altsize;
	VNICState *vsp = DO_UPCAST(VNICState, vns_nc, ncp);

	for (total = 0, i = 0; i < iovcnt; i++) {
		total += (iov + i)->iov_len;
	}

	if (vsp->vns_ds.vnds_enabled && get_ethertypev(iov, iovcnt, &ethtype)) {
		/*
		 * Basically drop the packet because we can't send a
		 * reply at this time. It's unfortunate, but we don't
		 * really have the proper infrastructure to do something
		 * else with this at this time.
		 */
		if (!vnic_can_send(vsp))
			return (total);

		VNICDHCPState *vdsp = &vsp->vns_ds;

		switch (ethtype) {
		case ETH_P_ARP:
			if (!is_arp_requestv(iov, iovcnt, vdsp))
				goto send;
			ret = create_arp_responsev(iov, iovcnt, vdsp);
			break;
		case ETH_P_IP:
			if (!is_dhcp_requestv(iov, iovcnt))
				goto send;
			ret = create_dhcp_responsev(iov, iovcnt, vdsp);
			break;
		default:
			goto send;
		}

		/* This failed, drop it and continue */
		if (ret == 0)
			return (total);

		ret = qemu_send_packet_async(&vsp->vns_nc,
		    vdsp->vnds_buf, ret, vnic_send_completed);
		/*
		 * qemu has told us that it can't receive any more data
		 * at this time for the guest (host->guest traffic) so
		 * turn off our read poll until we get that the send has
		 * completed.
		 */
		if (ret == 0)
			vnic_read_poll(vsp, 0);
		return (total);
	}

send:
	/*
	 * Copy the iovcs to our write frameio. Be on the lookout for someone
	 * giving us more vectors than we support in frameio. In that case,
	 * let's go ahead and just simply concat the rest.
	 */
	for (i = 0; i < MIN(iovcnt, FRAMEIO_NVECS_MAX - 1); i++, iov++) {
		vsp->vns_wfio->fio_vecs[i].fv_buf = iov->iov_base;
		vsp->vns_wfio->fio_vecs[i].fv_buflen = iov->iov_len;
	}

	altsize = 0;
	for (i = MIN(iovcnt, FRAMEIO_NVECS_MAX - 1); i != iovcnt; i++, iov++) {
		/*
		 * The packet is too large. We're goin to silently drop it...
		 */
		if (altsize + iov->iov_len > VNIC_BUFSIZE)
			return (total);

		bcopy(iov->iov_base, vsp->vns_txbuf + altsize, iov->iov_len);
		altsize += iov->iov_len;
	}
	if (altsize != 0) {
		vsp->vns_wfio->fio_vecs[FRAMEIO_NVECS_MAX-1].fv_buf =
		    vsp->vns_txbuf;
		vsp->vns_wfio->fio_vecs[FRAMEIO_NVECS_MAX-1].fv_buflen =
		    altsize;
	}

	vsp->vns_wfio->fio_nvecs = MIN(iovcnt, FRAMEIO_NVECS_MAX);
	vsp->vns_wfio->fio_nvpf = MIN(iovcnt, FRAMEIO_NVECS_MAX);
	do {
		ret = vnd_frameio_write(vsp->vns_hdl, vsp->vns_wfio);
	} while (ret == -1 && errno == EINTR);

	if (ret == -1 && errno == EAGAIN) {
		vnic_write_poll(vsp, 1);
		return (0);
	} else if (ret == -1) {
		abort();
	}

	total = 0;
	for (i = 0; i < vsp->vns_wfio->fio_nvecs; i++) {
		if (vsp->vns_wfio->fio_vecs[i].fv_actlen == 0 &&
		    vsp->vns_wfio->fio_vecs[i].fv_buflen == 0)
			break;

		total += vsp->vns_wfio->fio_vecs[i].fv_actlen;
	}

	return (total);
}

static void
vnic_cleanup(VLANClientState *ncp)
{
	VNICState *vsp;

	vsp = DO_UPCAST(VNICState, vns_nc, ncp);

	qemu_purge_queued_packets(ncp);

	vnd_close(vsp->vns_hdl);
}

static void
vnic_update_fd_handler(VNICState *vsp)
{
	qemu_set_fd_handler2(vsp->vns_fd,
	    vsp->vns_rpoll ? vnic_can_send : NULL,
	    vsp->vns_rpoll ? vnic_send : NULL,
	    vsp->vns_wpoll ? vnic_writable : NULL,
	    vsp);
}

static NetClientInfo net_vnic_info = {
	.type = NET_CLIENT_TYPE_VNIC,
	.size = sizeof (VNICState),
	.receive = vnic_receive,
	.receive_iov = vnic_receive_iov,
	.poll = vnic_poll,
	.cleanup = vnic_cleanup
};

/*
 * Set up all the known values for our frame I/O devices.
 */
static int
vnic_frameio_init(VNICState *vsp)
{
	vsp->vns_rfio = qemu_mallocz(sizeof (frameio_t) +
	    sizeof (framevec_t) * FRAMEIO_NVECS_MAX);
	if (vsp->vns_rfio == NULL)
		return (1);
	vsp->vns_wfio = qemu_mallocz(sizeof (frameio_t) +
	    sizeof (framevec_t) * FRAMEIO_NVECS_MAX);
	if (vsp->vns_wfio == NULL)
		return (1);
	vsp->vns_rfio->fio_version = FRAMEIO_CURRENT_VERSION;
	vsp->vns_rfio->fio_nvpf = 1;
	vsp->vns_wfio->fio_version = FRAMEIO_CURRENT_VERSION;
	vsp->vns_wfio->fio_nvpf = 1;
	return (0);
}

int
net_init_vnic(QemuOpts *opts, Monitor *mon, const char *name, VLANState *vlan)
{
	int fd, len, vnderr, syserr;
	const char *ifname, *mac;
	uchar_t *macaddr;
	VLANClientState *ncp;
	VNICState *vsp;
	vnd_prop_buf_t vib;

	if ((ifname = qemu_opt_get(opts, "ifname")) == NULL) {
		error_report("missing ifname required for vnic\n");
		return (-1);
	}

	mac = qemu_opt_get(opts, "macaddr");

	if (mac != NULL) {
		macaddr = _link_aton(mac, &len);
		if (macaddr == NULL || len != ETHERADDRL) {
			error_report("invalid macaddr for vnic: %s\n", mac);
			return (-1);
		}
	}

	ncp = qemu_new_net_client(&net_vnic_info, vlan, NULL, "vnic", name);
	vsp = DO_UPCAST(VNICState, vns_nc, ncp);


	vsp->vns_hdl = vnd_open(NULL, ifname, &vnderr, &syserr);
	if (vsp->vns_hdl == NULL) {
		const char *err = vnderr != VND_E_SYS ?
		    vnd_strerror(vnderr) : vnd_strsyserror(syserr);
		error_report("vnic: failed to open interface %s - %s\n",
		    ifname, err);
		return (-1);
	}

	vib.vpb_size = 1024 * 1024 * 4; 	/* 4 MB */
	if (vnd_prop_set(vsp->vns_hdl, VND_PROP_RXBUF, &vib,
	    sizeof (vib)) != 0) {
		const char *err = vnderr != VND_E_SYS ?
		    vnd_strerror(vnderr) : vnd_strsyserror(syserr);
		error_report("failed to change rx buf size: %s\n", err);
		return (-1);
	}

	vib.vpb_size = 1024 * 1024 * 4; 	/* 4 MB */
	if (vnd_prop_set(vsp->vns_hdl, VND_PROP_TXBUF, &vib,
	    sizeof (vib)) != 0) {
		const char *err = vnderr != VND_E_SYS ?
		    vnd_strerror(vnderr) : vnd_strsyserror(syserr);
		error_report("failed to change tx buf size: %s\n", err);
		return (-1);
	}


	fd = vnd_pollfd(vsp->vns_hdl);
	if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
		error_report("vnic: failed to set fd on interface %s to "
		    "non-blocking: %s\n", ifname, strerror(errno));
		return (-1);
	}

	vsp->vns_fd = fd;

	snprintf(vsp->vns_nc.info_str, sizeof (vsp->vns_nc.info_str),
	    "ifname=%s", qemu_opt_get(opts, "ifname"));

	if (vnic_dhcp_init(&vsp->vns_ds, opts) == 0)
		return (-1);

	if (vnic_frameio_init(vsp) != 0) {
		error_report("vnic: failed initialize frameio: %s\n",
		    strerror(errno));
		return (-1);
	}

	/* We have to manually intialize the polling for read */
	vnic_read_poll(vsp, 1);

	return (0);
}
