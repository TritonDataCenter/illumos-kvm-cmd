/*
 * QEMU System Emulator
 * Solaris VNIC DHCP support
 *
 * Copyright (c) 2011 Joyent, Inc.
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
#ifndef QEMU_NET_VNIC_DHCP_H
#define QEMU_NET_VNIC_DHCP_H

#include <netinet/in.h>
#include "qemu-option.h"

#define	VNIC_BUFFSIZE	65536
#define VNIC_DHCP_DEBUG 0
#define VNIC_DHCP_HEX_DUMP 0
#define VNIC_DHCP_NUM_RESOLVERS 4
#define VNIC_DHCP_HOSTNAME_LEN 255

typedef struct VNICDHCPState {
	unsigned int	vnds_enabled;
	uint8_t		vnds_buf[VNIC_BUFFSIZE];
	uint16_t	vnds_ip_id;
	struct in_addr	vnds_srv_addr;
	struct in_addr	vnds_client_addr;
	struct in_addr	vnds_netmask_addr;
	struct in_addr	vnds_gw_addr;
	struct in_addr	vnds_dns_addrs[VNIC_DHCP_NUM_RESOLVERS];
	uint32_t	vnds_lease_time;
	char		vnds_client_hostname[VNIC_DHCP_HOSTNAME_LEN];
	unsigned int	vnds_num_dns_addrs;
} VNICDHCPState;

int create_dhcp_response(const uint8_t *buf_p, int pkt_len, VNICDHCPState *vdsp);
int is_dhcp_request(const uint8_t *buf_p, size_t size);
int vnic_dhcp_init(VNICDHCPState *vdsp, QemuOpts *opts);
void debug_eth_frame(const uint8_t *buf_p, size_t size);

#endif /* QEMU_NET_VNIC_DHCP_H */
