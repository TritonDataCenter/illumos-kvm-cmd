#ifndef _COMPAT_SYS_EVENTFD
#define _COMPAT_SYS_EVENTFD

#include <unistd.h>
#include <syscall.h>


static inline int eventfd (int count, int flags)
{
    return syscall(SYS_eventfd, count, flags);
}

#endif
