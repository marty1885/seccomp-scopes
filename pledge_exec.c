#include <sys/syscall.h>  /* syscall numbers */

#include "bpf_helper.h"
#include "pledge_stdio.h"
#include "pledge_internal.h"

void append_exec_filter(unsigned int scopes, struct sock_fprog* prog) {
  if (!(scopes & SCOPE_PROC)) {
    return;
  }

  BPFINTO(prog) {
    _RET_EQ(__NR_execve,         SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_execveat,        SECCOMP_RET_ALLOW);
  }
}
