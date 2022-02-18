#include <sys/mman.h>  /* PROT_* flags */

#include <sys/syscall.h>  /* syscall numbers */

#include "bpf_helper.h"
#include "pledge_stdio.h"
#include "pledge_internal.h"


void append_stdio_filter(unsigned int scopes, struct sock_fprog* prog) {
  if (!(scopes & SCOPE_STDIO)) {
    return;
  }

  BPFINTO(prog) {
    // Reading and writing
    _RET_EQ(__NR_read,           SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_readv,          SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_pread64,        SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_preadv,         SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_preadv2,        SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_write,          SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_writev,         SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_pwrite64,       SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_pwritev,        SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_pwritev2,       SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_access,         SECCOMP_RET_ALLOW); // does this belong here?
    // Copying data between fds.
    _RET_EQ(__NR_sendfile,       SECCOMP_RET_ALLOW);
#ifdef __NR_sendfile64
    _RET_EQ(__NR_sendfile64,     SECCOMP_RET_ALLOW);
#endif  // __NR_sendfile64
    // Stat
    _RET_EQ(__NR_fstat,          SECCOMP_RET_ALLOW);
#ifdef __NR_fstat64
    _RET_EQ(__NR_fstat64,        SECCOMP_RET_ALLOW);
#endif  // __NR_fstat64
#ifdef __NR_newfstatat
    _RET_EQ(__NR_newfstatat,     SECCOMP_RET_ALLOW);
#endif  // __NR_newfstatat
    // Closing file descriptors
    _RET_EQ(__NR_close,          SECCOMP_RET_ALLOW);

    // file descriptor operations
    _RET_EQ(__NR_dup,            SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_dup2,           SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_dup3,           SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_fcntl,          SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_pipe,           SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_pipe2,          SECCOMP_RET_ALLOW);

    // socket
    _RET_EQ(__NR_recvfrom,       SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_recvmsg,        SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_recvmmsg,       SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_sendmsg,        SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_sendmmsg,       SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_sendto,         SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_socketpair,     SECCOMP_RET_ALLOW);

    // file synchronization
    _RET_EQ(__NR_fsync,          SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_fdatasync,      SECCOMP_RET_ALLOW);

    // misc
    _RET_EQ(__NR_fchdir,         SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_ftruncate,      SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_truncate,       SECCOMP_RET_ALLOW);
#ifdef __NR_getdents
    _RET_EQ(__NR_getdents,       SECCOMP_RET_ALLOW);
#endif
#ifdef __NR_getdents64
    _RET_EQ(__NR_getdents64,     SECCOMP_RET_ALLOW);
#endif
    _RET_EQ(__NR_getgid,         SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_getegid,        SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_getgroups,      SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_getpgid,        SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_getpid,         SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_getppid,        SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_getresgid,      SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_getresuid,      SECCOMP_RET_ALLOW);
#ifdef __NR_getrlimit
    _RET_EQ(__NR_getrlimit,      SECCOMP_RET_ALLOW);
#endif
    _RET_EQ(__NR_getsid,         SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_gettimeofday,   SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_getuid,         SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_lseek,          SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_umask,          SECCOMP_RET_ALLOW);
#ifdef __NR_ugetrlimit
    _RET_EQ(__NR_ugetrlimit,     SECCOMP_RET_ALLOW);
#endif
#ifdef __NR_getrandom
    _RET_EQ(__NR_getrandom,      SECCOMP_RET_ALLOW);
#endif
    _RET_EQ(__NR_syslog,         SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_shutdown,       SECCOMP_RET_ALLOW);

    // Timing
    _RET_EQ(__NR_getitimer,      SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_setitimer,      SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_nanosleep,      SECCOMP_RET_ALLOW);

    // memory. Handled by append_memory_filter
    // _RET_EQ(__NR_madvise,        SECCOMP_RET_ALLOW);
    // _RET_EQ(__NR_mmap,           SECCOMP_RET_ALLOW);
    // _RET_EQ(__NR_munmap,         SECCOMP_RET_ALLOW);
    // _RET_EQ(__NR_mprotect,       SECCOMP_RET_ALLOW);

    // Should I put pkey in stdio?
    _RET_EQ(__NR_pkey_mprotect,  SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_pkey_alloc,     SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_pkey_free,      SECCOMP_RET_ALLOW);

    // fd waiting
    _RET_EQ(__NR_epoll_create1,  SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_epoll_create,   SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_epoll_ctl,      SECCOMP_RET_ALLOW);
#ifdef __NR_epoll_ctl_oldl
    _RET_EQ(__NR_epoll_ctl_old,  SECCOMP_RET_ALLOW);
#endif
    _RET_EQ(__NR_epoll_pwait2,   SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_epoll_pwait,    SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_poll,           SECCOMP_RET_ALLOW);
#ifdef __NR_select
    _RET_EQ(__NR_select,         SECCOMP_RET_ALLOW);
#endif
#ifdef __NR_pselect6
    _RET_EQ(__NR_pselect6,       SECCOMP_RET_ALLOW);
#endif

    // io_uring
#ifdef __NR_io_uring_setup
  _RET_EQ(__NR_io_uring_setup,   SECCOMP_RET_ALLOW);
#endif
#ifdef __NR_io_uring_enter
  _RET_EQ(__NR_io_uring_enter,   SECCOMP_RET_ALLOW);
#endif
#ifdef __NR_io_uring_register
  _RET_EQ(__NR_io_uring_register,SECCOMP_RET_ALLOW);
#endif

    // Signal handling
    _RET_EQ(__NR_rt_sigaction,   SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_rt_sigprocmask, SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_rt_sigreturn,   SECCOMP_RET_ALLOW);


    // Locks...?
    _RET_EQ(__NR_get_robust_list,SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_set_robust_list,SECCOMP_RET_ALLOW);
#ifdef __NR_arch_prctl
    _RET_EQ(__NR_arch_prctl,     SECCOMP_RET_ALLOW);
#endif

    // exit
    _RET_EQ(__NR_exit,           SECCOMP_RET_ALLOW);
    _RET_EQ(0x5e,     SECCOMP_RET_ALLOW);
  }
}


void append_memory_filter(unsigned int scopes, struct sock_fprog* prog) {
  if (!(scopes & SCOPE_STDIO)) {
    return;
  }

  // PROT_EXEC is *not* allowed.
  int permitted_prot_flags = PROT_READ | PROT_WRITE;

  DECLARELABEL(out);
  BPFINTO(prog) {
    // Generic memory allocation
    _RET_EQ(__NR_brk,            SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_munmap,         SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_madvise,        SECCOMP_RET_ALLOW);

    // mmap(), mmap2(), mprotect() only allowed if prot is not PROT_EXEC
    //
    // if (nr == __NR_mmap2 || nr == __NR_mmap || nr == __NR_mprotect) {
    //   int prot = arg2;
    //   if ((prot | permitted_prot_flags) == permitted_prot_flags) {
    //     return SECCOMP_RET_ALLOW;
    //   }
    // }
#ifdef __NR_mmap2
    _JEQ(__NR_mmap2,    2 /* checkprot */, 0);
#endif  // __NR_mmap2

#ifdef __NR_mmap
    _JEQ(__NR_mmap,     1 /* checkprot */, 0);
#else
    _NOP();  // To keep jump sizes correct.
#endif  // __NR_mmap

    _JEQ(__NR_mprotect, 0 /* checkprot */, ELSE_TO(out));

    // checkprot:
    _LD_ARG(2);  // acc := prot (same arg position on all three syscalls)
    _OR(permitted_prot_flags);
    _RET_EQ(permitted_prot_flags, SECCOMP_RET_ALLOW);  // 2 instructions

    LABEL(out);
    _LD_NR();
  };
}
