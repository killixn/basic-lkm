#ifndef FTRACE_HELPER_H
#define FTRACE_HELPER_H

#include "hook.h"

int fh_install_hooks(struct ftrace_hook *hooks, size_t count);
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count);

#endif /* !FTRACE_HELPER_H */
