#include "hw/hw.h"
#include "hw/boards.h"

#include "exec-all.h"
#include "qemu-kvm.h"

void kvm_arch_save_mpstate(CPUState *env);
void kvm_arch_load_mpstate(CPUState *env);

void cpu_save(QEMUFile *f, void *opaque)
{
    CPUState *env = opaque;

    if (kvm_enabled()) {
        kvm_arch_save_mpstate(env);
    }
}

int cpu_load(QEMUFile *f, void *opaque, int version_id)
{
    CPUState *env = opaque;

    if (kvm_enabled()) {
        kvm_arch_load_mpstate(env);
    }
    return 0;
}

extern QEMUMachine ipf_machine;

static void ipf_machine_init(void)
{
    qemu_register_machine(&ipf_machine);
}

machine_init(ipf_machine_init);
