#include <sys/syscall.h>  /* syscall numbers */

#include "bpf_helper.h"
#include "pledge_stdio.h"
#include "pledge_internal.h"

void append_proc_filter(unsigned int scopes, struct sock_fprog* prog) {
  if (!(scopes & SCOPE_PROC)) {
    return;
  }

  BPFINTO(prog) {
    // Various fork system calls
    // TODO: This also prevents creation of new thread.
    _RET_EQ(__NR_vfork,          SECCOMP_RET_ALLOW);
	_RET_EQ(__NR_clone,          SECCOMP_RET_ALLOW);
    // Other process related syscalls
    _RET_EQ(__NR_kill,           SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_getpriority,    SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_setpriority,    SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_setrlimit,      SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_setpgid,        SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_setsid,         SECCOMP_RET_ALLOW);

    // NOTE: These are not in OpenBSD's doc
#ifdef __NR_wait3
    _RET_EQ(__NR_wait3,          SECCOMP_RET_ALLOW);
#endif
    _RET_EQ(__NR_wait4,          SECCOMP_RET_ALLOW);
  }
}