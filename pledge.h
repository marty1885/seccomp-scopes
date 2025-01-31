
/*
 * The current process is forced into a restricted-service operating mode.
 *
 * An OpenBSD-like pledge implementation.
 *
 * @promises is a space-separated set of keywords:
 *
 *   stdio  Permit most basic libc functions, including memory allocation and
 *          most types of IO operations on previously allocated file
 *          descriptors.
 *
 *   rpath  Permit opening files for reading
 *
 *   wpath  Permit opening files for writing
 *
 *   cpath  Permit creating files
 *
 *   inet   The following syscalls are allowed to operate in the AF_INET
 *          and AF_INET6 domains:
 *
 *          from OpenBSD: socket(2), listen(2), bind(2), connect(2),
 *          accept4(2), accept(2), getpeername(2), getsockname(2),
 *          setsockopt(2), getsockopt(2)
 * 
 *   exec   Allows a process to call execve(2). Since this implemetation
 *          does not support execpromises. There's no exception
 * 
 *   proc   Allows the following process relationship operations:
 *
 *          fork(2), vfork(2), kill(2), getpriority(2), setpriority(2)
 *          , setrlimit(2), setpgid(2), setsid(2), wait3(3), wait4(4)
 *
 *   ...
 *
 * @paths is a list of paths.  This is not currently supported on Linux.
 *
 * Returns 0 on success.  Otherwise, returns -1 and errno will be set.
 */
int pledge(const char* promises, const char* paths[]);
