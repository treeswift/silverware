#ifndef _WIN_UNISTD_H
#define _WIN_UNISTD_H

#include <sys/types.h>
#include <windows.h>
#include <process.h>

#ifndef HAVE_PID_T
#define HAVE_PID_T
typedef intptr_t pid_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

pid_t getpid(void);

pid_t fork(void); /* not defined, therefore needs no aliasing */

#define AgWare_PREFIX silver
#define AgWare(func_name) AgWare_PREFIX ## func_name

/**
 * MSVCRT:
 * - no-_* names are disabled with __STDC__;
 * - exec return type is intptr_t (=int unless _WIN64, otherwise __int64)
 * MinGW:
 * - no-_* names are disabled with NO_OLDNAMES;
 * - exec return type is intptr_t unless __GNUC__, otherwise regular int.
 *
 * Function aliases are NOT implemented with macros, therefore no #ifdef/#undef;
 * we, however, use compile-time macro substitution, and our implementations use
 * the underscored versions of the functions to resolve any ambiguity.
 */ 

#define execl AgWare(execl)
#define execle AgWare(execle)
#define execlp AgWare(execlp)
#define execlpe AgWare(execlpe)

#define execv AgWare(execv)
#define execve AgWare(execve)
#define execvp AgWare(execvp)
#define execvpe AgWare(execvpe)

int execl(const char *pathname, const char *arg, ...);  /* ... ends with NULL */
int execle(const char *pathname, const char *arg, ...); /* ... ends with NULL */
int execlp(const char *filename, const char *arg, ...); /* ... ends with NULL and envp */
int execlpe(const char *filename, const char *arg, ...); /* ... ends with NULL and envp */

int execv(const char *pathname, const char *const argv[]);
int execve(const char *pathname, const char *const argv[], const char *const envp[]);
int execvp(const char *filename, const char *const argv[]);
int execvpe(const char *filename, const char *const argv[], const char *const envp[]);

#define exit AgWare(exit)

void exit(int status);

#define dup AgWare(dup)
#define dup2 AgWare(dup2)
#define dup3 AgWare(dup3)

int dup(int oldfd);
int dup2(int oldfd, int newfd);
int dup3(int oldfd, int newfd, int flags);

int fcntl(int fd, int cmd, ...);

#ifdef __cplusplus
}
#endif

#endif /* _WIN_UNISTD_H */