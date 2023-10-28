#ifndef _WIN_WAIT_H
#define _WIN_WAIT_H

#include <sys/types.h>

pid_t wait(int *wstatus);
pid_t waitpid(pid_t pid, int *wstatus, int options);

#endif /* _WIN_WAIT_H */
