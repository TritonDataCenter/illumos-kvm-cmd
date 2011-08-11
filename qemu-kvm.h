/*
 * qemu/kvm integration
 *
 * Copyright (C) 2006-2008 Qumranet Technologies
 * Portions Copyright 2011 Joyent, Inc.
 *
 * Licensed under the terms of the GNU GPL version 2 or higher.
 */
#ifndef THE_ORIGINAL_AND_TRUE_QEMU_KVM_H
#define THE_ORIGINAL_AND_TRUE_QEMU_KVM_H

#include "cpu.h"

#include <signal.h>
#include <stdlib.h>

#ifdef CONFIG_KVM

#if defined(__s390__)
#include <asm/ptrace.h>
#endif

#include <stdint.h>

#ifndef __user
#define __user       /* temporary, until installed via make headers_install */
#endif

#ifdef __sun__
#include <sys/kvm.h>
#else
#include <linux/kvm.h>
#endif

#include <signal.h>

/* FIXME: share this number with kvm */
/* FIXME: or dynamically alloc/realloc regions */
#ifdef __s390__
#define KVM_MAX_NUM_MEM_REGIONS 1u
#define MAX_VCPUS 64
#define LIBKVM_S390_ORIGIN (0UL)
#elif defined(__ia64__)
#define KVM_MAX_NUM_MEM_REGIONS 32u
#define MAX_VCPUS 256
#else
#define KVM_MAX_NUM_MEM_REGIONS 32u
#define MAX_VCPUS 16
#endif

/* kvm abi verison variable */
extern int kvm_abi;

/**
 * \brief The KVM context
 *
 * The verbose KVM context
 */

struct kvm_context {
    void *opaque;
    /// is dirty pages logging enabled for all regions or not
    int dirty_pages_log_all;
    /// do not create in-kernel irqchip if set
    int no_irqchip_creation;
    /// in-kernel irqchip status
    int irqchip_in_kernel;
    /// ioctl to use to inject interrupts
    int irqchip_inject_ioctl;
    /// do not create in-kernel pit if set
    int no_pit_creation;
#ifdef KVM_CAP_IRQ_ROUTING
    struct kvm_irq_routing *irq_routes;
    int nr_allocated_irq_routes;
#endif
    void *used_gsi_bitmap;
    int max_gsi;
};

typedef struct kvm_context *kvm_context_t;

#include "kvm.h"
int kvm_alloc_kernel_memory(kvm_context_t kvm, unsigned long memory,
                            void **vm_mem);
int kvm_alloc_userspace_memory(kvm_context_t kvm, unsigned long memory,
                               void **vm_mem);

int kvm_arch_create(kvm_context_t kvm, unsigned long phys_mem_bytes,
                    void **vm_mem);

int kvm_arch_run(CPUState *env);


void kvm_show_code(CPUState *env);

int handle_halt(CPUState *env);

int handle_shutdown(kvm_context_t kvm, CPUState *env);
void post_kvm_run(kvm_context_t kvm, CPUState *env);
int pre_kvm_run(kvm_context_t kvm, CPUState *env);
int handle_io_window(kvm_context_t kvm);
int try_push_interrupts(kvm_context_t kvm);

#if defined(__x86_64__) || defined(__i386__)
struct kvm_x86_mce;
#endif

/*!
 * \brief Disable the in-kernel IRQCHIP creation
 *
 * In-kernel irqchip is enabled by default. If userspace irqchip is to be used,
 * this should be called prior to kvm_create().
 *
 * \param kvm Pointer to the kvm_context
 */
void kvm_disable_irqchip_creation(kvm_context_t kvm);

/*!
 * \brief Disable the in-kernel PIT creation
 *
 * In-kernel pit is enabled by default. If userspace pit is to be used,
 * this should be called prior to kvm_create().
 *
 *  \param kvm Pointer to the kvm_context
 */
void kvm_disable_pit_creation(kvm_context_t kvm);

/*!
 * \brief Create new virtual machine
 *
 * This creates a new virtual machine, maps physical RAM to it, and creates a
 * virtual CPU for it.\n
 * \n
 * Memory gets mapped for addresses 0->0xA0000, 0xC0000->phys_mem_bytes
 *
 * \param kvm Pointer to the current kvm_context
 * \param phys_mem_bytes The amount of physical ram you want the VM to have
 * \param phys_mem This pointer will be set to point to the memory that
 * kvm_create allocates for physical RAM
 * \return 0 on success
 */
int kvm_create(kvm_context_t kvm, unsigned long phys_mem_bytes,
               void **phys_mem);
int kvm_create_vm(kvm_context_t kvm);
void kvm_create_irqchip(kvm_context_t kvm);

/*!
 * \brief Start the VCPU
 *
 * This starts the VCPU and virtualization is started.\n
 * \n
 * This function will not return until any of these conditions are met:
 * - An IO/MMIO handler does not return "0"
 * - An exception that neither the guest OS, nor KVM can handle occurs
 *
 * \note This function will call the callbacks registered in kvm_init()
 * to emulate those functions
 * \note If you at any point want to interrupt the VCPU, kvm_run() will
 * listen to the EINTR signal. This allows you to simulate external interrupts
 * and asyncronous IO.
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should be started
 * \return 0 on success, but you really shouldn't expect this function to
 * return except for when an error has occured, or when you have sent it
 * an EINTR signal.
 */
int kvm_run(CPUState *env);

/*!
 * \brief Check if a vcpu is ready for interrupt injection
 *
 * This checks if vcpu interrupts are not masked by mov ss or sti.
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should get dumped
 * \return boolean indicating interrupt injection readiness
 */
int kvm_is_ready_for_interrupt_injection(CPUState *env);

/*!
 * \brief Read VCPU registers
 *
 * This gets the GP registers from the VCPU and outputs them
 * into a kvm_regs structure
 *
 * \note This function returns a \b copy of the VCPUs registers.\n
 * If you wish to modify the VCPUs GP registers, you should call kvm_set_regs()
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should get dumped
 * \param regs Pointer to a kvm_regs which will be populated with the VCPUs
 * registers values
 * \return 0 on success
 */
int kvm_get_regs(CPUState *env, struct kvm_regs *regs);

/*!
 * \brief Write VCPU registers
 *
 * This sets the GP registers on the VCPU from a kvm_regs structure
 *
 * \note When this function returns, the regs pointer and the data it points to
 * can be discarded
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should get dumped
 * \param regs Pointer to a kvm_regs which will be populated with the VCPUs
 * registers values
 * \return 0 on success
 */
int kvm_set_regs(CPUState *env, struct kvm_regs *regs);

#ifdef KVM_CAP_MP_STATE
/*!
 *  * \brief Read VCPU MP state
 *
 */
int kvm_get_mpstate(CPUState *env, struct kvm_mp_state *mp_state);

/*!
 *  * \brief Write VCPU MP state
 *
 */
int kvm_set_mpstate(CPUState *env, struct kvm_mp_state *mp_state);
#endif

#if defined(__i386__) || defined(__x86_64__)
/*!
 * \brief Simulate an external vectored interrupt
 *
 * This allows you to simulate an external vectored interrupt.
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should get dumped
 * \param irq Vector number
 * \return 0 on success
 */
int kvm_inject_irq(CPUState *env, unsigned irq);


/*!
 * \brief Setting the number of shadow pages to be allocated to the vm
 *
 * \param kvm pointer to kvm_context
 * \param nrshadow_pages number of pages to be allocated
 */
int kvm_set_shadow_pages(kvm_context_t kvm, unsigned int nrshadow_pages);

/*!
 * \brief Getting the number of shadow pages that are allocated to the vm
 *
 * \param kvm pointer to kvm_context
 * \param nrshadow_pages number of pages to be allocated
 */
int kvm_get_shadow_pages(kvm_context_t kvm, unsigned int *nrshadow_pages);

#endif

/*!
 * \brief Dump VCPU registers
 *
 * This dumps some of the information that KVM has about a virtual CPU, namely:
 * - GP Registers
 *
 * A much more verbose version of this is available as kvm_dump_vcpu()
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should get dumped
 * \return 0 on success
 */
void kvm_show_regs(CPUState *env);


void *kvm_create_phys_mem(kvm_context_t, unsigned long phys_start,
                          unsigned long len, int log, int writable);
void kvm_destroy_phys_mem(kvm_context_t, unsigned long phys_start,
                          unsigned long len);

int kvm_is_containing_region(kvm_context_t kvm, unsigned long phys_start,
                             unsigned long size);
int kvm_register_phys_mem(kvm_context_t kvm, unsigned long phys_start,
                          void *userspace_addr, unsigned long len, int log);
int kvm_get_dirty_pages_range(kvm_context_t kvm, unsigned long phys_addr,
                              unsigned long end_addr, void *opaque,
                              int (*cb)(unsigned long start,
                                        unsigned long len, void *bitmap,
                                        void *opaque));
int kvm_register_coalesced_mmio(kvm_context_t kvm, uint64_t addr,
                                uint32_t size);
int kvm_unregister_coalesced_mmio(kvm_context_t kvm, uint64_t addr,
                                  uint32_t size);

/*!
 * \brief Get a bitmap of guest ram pages which are allocated to the guest.
 *
 * \param kvm Pointer to the current kvm_context
 * \param phys_addr Memory slot phys addr
 * \param bitmap Long aligned address of a big enough bitmap (one bit per page)
 */
int kvm_get_mem_map(kvm_context_t kvm, unsigned long phys_addr, void *bitmap);
int kvm_get_mem_map_range(kvm_context_t kvm, unsigned long phys_addr,
                          unsigned long len, void *buf, void *opaque,
                          int (*cb)(unsigned long start,
                                    unsigned long len, void *bitmap,
                                    void *opaque));
int kvm_set_irq_level(kvm_context_t kvm, int irq, int level, int *status);

int kvm_dirty_pages_log_enable_slot(kvm_context_t kvm, uint64_t phys_start,
                                    uint64_t len);
int kvm_dirty_pages_log_disable_slot(kvm_context_t kvm, uint64_t phys_start,
                                     uint64_t len);
/*!
 * \brief Enable dirty-pages-logging for all memory regions
 *
 * \param kvm Pointer to the current kvm_context
 */
int kvm_dirty_pages_log_enable_all(kvm_context_t kvm);

/*!
 * \brief Disable dirty-page-logging for some memory regions
 *
 * Disable dirty-pages-logging for those memory regions that were
 * created with dirty-page-logging disabled.
 *
 * \param kvm Pointer to the current kvm_context
 */
int kvm_dirty_pages_log_reset(kvm_context_t kvm);

#ifdef KVM_CAP_IRQCHIP
/*!
 * \brief Dump in kernel IRQCHIP contents
 *
 * Dump one of the in kernel irq chip devices, including PIC (master/slave)
 * and IOAPIC into a kvm_irqchip structure
 *
 * \param kvm Pointer to the current kvm_context
 * \param chip The irq chip device to be dumped
 */
int kvm_get_irqchip(kvm_context_t kvm, struct kvm_irqchip *chip);

/*!
 * \brief Set in kernel IRQCHIP contents
 *
 * Write one of the in kernel irq chip devices, including PIC (master/slave)
 * and IOAPIC
 *
 *
 * \param kvm Pointer to the current kvm_context
 * \param chip THe irq chip device to be written
 */
int kvm_set_irqchip(kvm_context_t kvm, struct kvm_irqchip *chip);

#if defined(__i386__) || defined(__x86_64__)
/*!
 * \brief Get in kernel local APIC for vcpu
 *
 * Save the local apic state including the timer of a virtual CPU
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should be accessed
 * \param s Local apic state of the specific virtual CPU
 */
int kvm_get_lapic(CPUState *env, struct kvm_lapic_state *s);

/*!
 * \brief Set in kernel local APIC for vcpu
 *
 * Restore the local apic state including the timer of a virtual CPU
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should be accessed
 * \param s Local apic state of the specific virtual CPU
 */
int kvm_set_lapic(CPUState *env, struct kvm_lapic_state *s);

#endif

/*!
 * \brief Simulate an NMI
 *
 * This allows you to simulate a non-maskable interrupt.
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should get dumped
 * \return 0 on success
 */
int kvm_inject_nmi(CPUState *env);

#endif

/*!
 * \brief Initialize coalesced MMIO
 *
 * Check for coalesced MMIO capability and store in context
 *
 * \param kvm Pointer to the current kvm_context
 */
int kvm_init_coalesced_mmio(kvm_context_t kvm);

#ifdef KVM_CAP_PIT

#if defined(__i386__) || defined(__x86_64__)
/*!
 * \brief Get in kernel PIT of the virtual domain
 *
 * Save the PIT state.
 *
 * \param kvm Pointer to the current kvm_context
 * \param s PIT state of the virtual domain
 */
int kvm_get_pit(kvm_context_t kvm, struct kvm_pit_state *s);

/*!
 * \brief Set in kernel PIT of the virtual domain
 *
 * Restore the PIT state.
 * Timer would be retriggerred after restored.
 *
 * \param kvm Pointer to the current kvm_context
 * \param s PIT state of the virtual domain
 */
int kvm_set_pit(kvm_context_t kvm, struct kvm_pit_state *s);

int kvm_reinject_control(kvm_context_t kvm, int pit_reinject);

#ifdef KVM_CAP_PIT_STATE2
/*!
 * \brief Check for kvm support of kvm_pit_state2
 *
 * \param kvm Pointer to the current kvm_context
 * \return 0 on success
 */
int kvm_has_pit_state2(kvm_context_t kvm);

/*!
 * \brief Set in kernel PIT state2 of the virtual domain
 *
 *
 * \param kvm Pointer to the current kvm_context
 * \param ps2 PIT state2 of the virtual domain
 * \return 0 on success
 */
int kvm_set_pit2(kvm_context_t kvm, struct kvm_pit_state2 *ps2);

/*!
 * \brief Get in kernel PIT state2 of the virtual domain
 *
 *
 * \param kvm Pointer to the current kvm_context
 * \param ps2 PIT state2 of the virtual domain
 * \return 0 on success
 */
int kvm_get_pit2(kvm_context_t kvm, struct kvm_pit_state2 *ps2);

#endif
#endif
#endif

#ifdef KVM_CAP_VAPIC

int kvm_enable_vapic(CPUState *env, uint64_t vapic);

#endif

#if defined(__s390__)
int kvm_s390_initial_reset(kvm_context_t kvm, int slot);
int kvm_s390_interrupt(kvm_context_t kvm, int slot,
                       struct kvm_s390_interrupt *kvmint);
int kvm_s390_set_initial_psw(kvm_context_t kvm, int slot, psw_t psw);
int kvm_s390_store_status(kvm_context_t kvm, int slot, unsigned long addr);
#endif

#ifdef KVM_CAP_DEVICE_ASSIGNMENT
/*!
 * \brief Notifies host kernel about a PCI device to be assigned to a guest
 *
 * Used for PCI device assignment, this function notifies the host
 * kernel about the assigning of the physical PCI device to a guest.
 *
 * \param kvm Pointer to the current kvm_context
 * \param assigned_dev Parameters, like bus, devfn number, etc
 */
int kvm_assign_pci_device(kvm_context_t kvm,
                          struct kvm_assigned_pci_dev *assigned_dev);

/*!
 * \brief Assign IRQ for an assigned device
 *
 * Used for PCI device assignment, this function assigns IRQ numbers for
 * an physical device and guest IRQ handling.
 *
 * \param kvm Pointer to the current kvm_context
 * \param assigned_irq Parameters, like dev id, host irq, guest irq, etc
 */
int kvm_assign_irq(kvm_context_t kvm, struct kvm_assigned_irq *assigned_irq);

#ifdef KVM_CAP_ASSIGN_DEV_IRQ
/*!
 * \brief Deassign IRQ for an assigned device
 *
 * Used for PCI device assignment, this function deassigns IRQ numbers
 * for an assigned device.
 *
 * \param kvm Pointer to the current kvm_context
 * \param assigned_irq Parameters, like dev id, host irq, guest irq, etc
 */
int kvm_deassign_irq(kvm_context_t kvm, struct kvm_assigned_irq *assigned_irq);
#endif
#endif

#ifdef KVM_CAP_DEVICE_DEASSIGNMENT
/*!
 * \brief Notifies host kernel about a PCI device to be deassigned from a guest
 *
 * Used for hot remove PCI device, this function notifies the host
 * kernel about the deassigning of the physical PCI device from a guest.
 *
 * \param kvm Pointer to the current kvm_context
 * \param assigned_dev Parameters, like bus, devfn number, etc
 */
int kvm_deassign_pci_device(kvm_context_t kvm,
                            struct kvm_assigned_pci_dev *assigned_dev);
#endif

/*!
 * \brief Determines the number of gsis that can be routed
 *
 * Returns the number of distinct gsis that can be routed by kvm.  This is
 * also the number of distinct routes (if a gsi has two routes, than another
 * gsi cannot be used...)
 *
 * \param kvm Pointer to the current kvm_context
 */
int kvm_get_gsi_count(kvm_context_t kvm);

/*!
 * \brief Clears the temporary irq routing table
 *
 * Clears the temporary irq routing table.  Nothing is committed to the
 * running VM.
 *
 */
int kvm_clear_gsi_routes(void);

/*!
 * \brief Adds an irq route to the temporary irq routing table
 *
 * Adds an irq route to the temporary irq routing table.  Nothing is
 * committed to the running VM.
 */
int kvm_add_irq_route(int gsi, int irqchip, int pin);

/*!
 * \brief Removes an irq route from the temporary irq routing table
 *
 * Adds an irq route to the temporary irq routing table.  Nothing is
 * committed to the running VM.
 */
int kvm_del_irq_route(int gsi, int irqchip, int pin);

struct kvm_irq_routing_entry;
/*!
 * \brief Adds a routing entry to the temporary irq routing table
 *
 * Adds a filled routing entry to the temporary irq routing table. Nothing is
 * committed to the running VM.
 */
int kvm_add_routing_entry(struct kvm_irq_routing_entry *entry);

/*!
 * \brief Removes a routing from the temporary irq routing table
 *
 * Remove a routing to the temporary irq routing table.  Nothing is
 * committed to the running VM.
 */
int kvm_del_routing_entry(struct kvm_irq_routing_entry *entry);

/*!
 * \brief Updates a routing in the temporary irq routing table
 *
 * Update a routing in the temporary irq routing table
 * with a new value. entry type and GSI can not be changed.
 * Nothing is committed to the running VM.
 */
int kvm_update_routing_entry(struct kvm_irq_routing_entry *entry,
                             struct kvm_irq_routing_entry *newentry);


/*!
 * \brief Create a file descriptor for injecting interrupts
 *
 * Creates an eventfd based file-descriptor that maps to a specific GSI
 * in the guest.  eventfd compliant signaling (write() from userspace, or
 * eventfd_signal() from kernelspace) will cause the GSI to inject
 * itself into the guest at the next available window.
 *
 * \param kvm Pointer to the current kvm_context
 * \param gsi GSI to assign to this fd
 * \param flags reserved, must be zero
 */
int kvm_irqfd(kvm_context_t kvm, int gsi, int flags);

#ifdef KVM_CAP_DEVICE_MSIX
int kvm_assign_set_msix_nr(kvm_context_t kvm,
                           struct kvm_assigned_msix_nr *msix_nr);
int kvm_assign_set_msix_entry(kvm_context_t kvm,
                              struct kvm_assigned_msix_entry *entry);
#endif

#else                           /* !CONFIG_KVM */

typedef struct kvm_context *kvm_context_t;
typedef struct kvm_vcpu_context *kvm_vcpu_context_t;

struct kvm_pit_state {
};

#endif                          /* !CONFIG_KVM */


/*!
 * \brief Create new KVM context
 *
 * This creates a new kvm_context. A KVM context is a small area of data that
 * holds information about the KVM instance that gets created by this call.\n
 * This should always be your first call to KVM.
 *
 * \param opaque Not used
 * \return NULL on failure
 */
int kvm_init(void);

int kvm_main_loop(void);
int kvm_init_ap(void);
int kvm_vcpu_inited(CPUState *env);
void kvm_save_lapic(CPUState *env);
void kvm_load_lapic(CPUState *env);

void kvm_hpet_enable_kpit(void);
void kvm_hpet_disable_kpit(void);

int kvm_physical_memory_set_dirty_tracking(int enable);

void on_vcpu(CPUState *env, void (*func)(void *data), void *data);
void qemu_kvm_call_with_env(void (*func)(void *), void *data, CPUState *env);
void qemu_kvm_cpuid_on_env(CPUState *env);
void kvm_inject_interrupt(CPUState *env, int mask);
void kvm_update_after_sipi(CPUState *env);
void kvm_update_interrupt_request(CPUState *env);
#ifndef CONFIG_USER_ONLY
void *kvm_cpu_create_phys_mem(target_phys_addr_t start_addr, unsigned long size,
                              int log, int writable);

void kvm_cpu_destroy_phys_mem(target_phys_addr_t start_addr,
                              unsigned long size);
void kvm_qemu_log_memory(target_phys_addr_t start, target_phys_addr_t size,
                         int log);
#endif
int kvm_qemu_create_memory_alias(uint64_t phys_start, uint64_t len,
                                 uint64_t target_phys);
int kvm_qemu_destroy_memory_alias(uint64_t phys_start);

int kvm_arch_qemu_create_context(void);

void kvm_arch_save_regs(CPUState *env);
void kvm_arch_load_regs(CPUState *env, int level);
int kvm_arch_has_work(CPUState *env);
void kvm_arch_process_irqchip_events(CPUState *env);
int kvm_arch_try_push_interrupts(void *opaque);
void kvm_arch_push_nmi(void *opaque);
void kvm_arch_cpu_reset(CPUState *env);
int kvm_set_boot_cpu_id(uint32_t id);

void qemu_kvm_aio_wait_start(void);
void qemu_kvm_aio_wait(void);
void qemu_kvm_aio_wait_end(void);

void kvm_tpr_access_report(CPUState *env, uint64_t rip, int is_write);

int kvm_arch_init_irq_routing(void);

int kvm_mmio_read(void *opaque, uint64_t addr, uint8_t * data, int len);
int kvm_mmio_write(void *opaque, uint64_t addr, uint8_t * data, int len);

#ifdef CONFIG_KVM_DEVICE_ASSIGNMENT
struct ioperm_data;

void kvm_ioperm(CPUState *env, void *data);
void kvm_add_ioperm_data(struct ioperm_data *data);
void kvm_remove_ioperm_data(unsigned long start_port, unsigned long num);
void kvm_arch_do_ioperm(void *_data);
#endif

#define ALIGN(x, y)  (((x)+(y)-1) & ~((y)-1))
#define BITMAP_SIZE(m) (ALIGN(((m)>>TARGET_PAGE_BITS), HOST_LONG_BITS) / 8)

#ifdef CONFIG_KVM
#include "qemu-queue.h"

extern int kvm_irqchip;
extern int kvm_pit;
extern int kvm_pit_reinject;
extern int kvm_nested;
extern kvm_context_t kvm_context;

struct ioperm_data {
    unsigned long start_port;
    unsigned long num;
    int turn_on;
    QLIST_ENTRY(ioperm_data) entries;
};

void qemu_kvm_cpu_stop(CPUState *env);
int kvm_arch_halt(CPUState *env);
int handle_tpr_access(void *opaque, CPUState *env, uint64_t rip,
                      int is_write);

#define qemu_kvm_has_gsi_routing() kvm_has_gsi_routing()
#ifdef TARGET_I386
#define qemu_kvm_has_pit_state2() kvm_has_pit_state2(kvm_context)
#endif
#else
#define kvm_nested 0
#define qemu_kvm_has_gsi_routing() (0)
#ifdef TARGET_I386
#define qemu_kvm_has_pit_state2() (0)
#endif
#define qemu_kvm_cpu_stop(env) do {} while(0)
#endif

#ifdef CONFIG_KVM

typedef struct KVMSlot {
    target_phys_addr_t start_addr;
    ram_addr_t memory_size;
    ram_addr_t phys_offset;
    int slot;
    int flags;
} KVMSlot;

typedef struct kvm_dirty_log KVMDirtyLog;

struct KVMState {
    KVMSlot slots[32];
    int fd;
    int vmfd;
    int coalesced_mmio;
#ifdef KVM_CAP_COALESCED_MMIO
    struct kvm_coalesced_mmio_ring *coalesced_mmio_ring;
#endif
    int broken_set_mem_region;
    int migration_log;
    int vcpu_events;
    int robust_singlestep;
    int debugregs;
#ifdef KVM_CAP_SET_GUEST_DEBUG
    QTAILQ_HEAD(, kvm_sw_breakpoint) kvm_sw_breakpoints;
#endif
    int irqchip_in_kernel;
    int pit_in_kernel;
    int xsave, xcrs;
    int many_ioeventfds;

    struct kvm_context kvm_context;
};

extern struct KVMState *kvm_state;

int kvm_tpr_enable_vapic(CPUState *env);

unsigned long kvm_get_thread_id(void);
int kvm_cpu_is_stopped(CPUState *env);

#endif

#endif
