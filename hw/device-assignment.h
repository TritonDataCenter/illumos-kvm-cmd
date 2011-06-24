/*
 * Copyright (c) 2007, Neocleus Corporation.
 * Copyright (c) 2007, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 *  Data structures for storing PCI state
 *
 *  Adapted to kvm by Qumranet
 *
 *  Copyright (c) 2007, Neocleus, Alex Novik (alex@neocleus.com)
 *  Copyright (c) 2007, Neocleus, Guy Zana (guy@neocleus.com)
 *  Copyright (C) 2008, Qumranet, Amit Shah (amit.shah@qumranet.com)
 *  Copyright (C) 2008, Red Hat, Amit Shah (amit.shah@redhat.com)
 */

#ifndef __DEVICE_ASSIGNMENT_H__
#define __DEVICE_ASSIGNMENT_H__

#include <sys/mman.h>
#include "qemu-common.h"
#include "qemu-queue.h"
#include "pci.h"

/* From include/linux/pci.h in the kernel sources */
#define PCI_DEVFN(slot, func)   ((((slot) & 0x1f) << 3) | ((func) & 0x07))

typedef struct PCIHostDevice {
    int seg;
    int bus;
    int dev;
    int func;
} PCIHostDevice;

typedef struct {
    int type;           /* Memory or port I/O */
    int valid;
    uint32_t base_addr;
    uint32_t size;    /* size of the region */
    int resource_fd;
} PCIRegion;

typedef struct {
    uint8_t bus, dev, func; /* Bus inside domain, device and function */
    int irq;                /* IRQ number */
    uint16_t region_number; /* number of active regions */

    /* Port I/O or MMIO Regions */
    PCIRegion regions[PCI_NUM_REGIONS - 1];
    int config_fd;
} PCIDevRegions;

typedef struct {
    pcibus_t e_physbase;
    ram_addr_t memory_index;
    union {
        void *r_virtbase;    /* mmapped access address for memory regions */
        uint32_t r_baseport; /* the base guest port for I/O regions */
    } u;
    int num;            /* our index within v_addrs[] */
    pcibus_t e_size;    /* emulated size of region in bytes */
    pcibus_t r_size;    /* real size of region in bytes */
    PCIRegion *region;
} AssignedDevRegion;

#define ASSIGNED_DEVICE_USE_IOMMU_BIT	0
#define ASSIGNED_DEVICE_PREFER_MSI_BIT	1

#define ASSIGNED_DEVICE_USE_IOMMU_MASK	(1 << ASSIGNED_DEVICE_USE_IOMMU_BIT)
#define ASSIGNED_DEVICE_PREFER_MSI_MASK	(1 << ASSIGNED_DEVICE_PREFER_MSI_BIT)

typedef struct AssignedDevice {
    PCIDevice dev;
    PCIHostDevice host;
    uint32_t features;
    int intpin;
    uint8_t debug_flags;
    AssignedDevRegion v_addrs[PCI_NUM_REGIONS - 1];
    PCIDevRegions real_device;
    int run;
    int girq;
    unsigned int h_segnr;
    unsigned char h_busnr;
    unsigned int h_devfn;
    int irq_requested_type;
    int bound;
    struct {
#define ASSIGNED_DEVICE_CAP_MSI (1 << 0)
#define ASSIGNED_DEVICE_CAP_MSIX (1 << 1)
        uint32_t available;
#define ASSIGNED_DEVICE_MSI_ENABLED (1 << 0)
#define ASSIGNED_DEVICE_MSIX_ENABLED (1 << 1)
#define ASSIGNED_DEVICE_MSIX_MASKED (1 << 2)
        uint32_t state;
    } cap;
    int irq_entries_nr;
    struct kvm_irq_routing_entry *entry;
    void *msix_table_page;
    target_phys_addr_t msix_table_addr;
    int mmio_index;
    int need_emulate_cmd;
    char *configfd_name;
    int32_t bootindex;
    QLIST_ENTRY(AssignedDevice) next;
} AssignedDevice;

void assigned_dev_update_irqs(void);

#endif              /* __DEVICE_ASSIGNMENT_H__ */
