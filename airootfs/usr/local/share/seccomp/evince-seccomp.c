#include <seccomp.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define ALLOW_RULE(call) { if (seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS(call), 0) < 0) goto out; }

int main(int argc, char *argv[])
{
    int rc = -1;
    scmp_filter_ctx ctx;
    int filter_fd;

    /* for whitelisting */

    ctx = seccomp_init(SCMP_ACT_KILL);
    if (ctx == NULL)
         goto out;

    ALLOW_RULE (recvmsg);
    ALLOW_RULE (poll);
    ALLOW_RULE (futex);
    ALLOW_RULE (read);
    ALLOW_RULE (writev);
    ALLOW_RULE (write);
    ALLOW_RULE (pread64);
    ALLOW_RULE (stat);
    ALLOW_RULE (lstat);
    ALLOW_RULE (mprotect);
    ALLOW_RULE (mincore);
    ALLOW_RULE (open);
    ALLOW_RULE (close);
    ALLOW_RULE (mmap);
    ALLOW_RULE (fstat);
    ALLOW_RULE (access);
    ALLOW_RULE (sendmsg);
    ALLOW_RULE (rt_sigaction);
    ALLOW_RULE (munmap);
    ALLOW_RULE (eventfd2);
    ALLOW_RULE (lseek);
    ALLOW_RULE (brk);
    ALLOW_RULE (select);
    ALLOW_RULE (fstatfs);
    ALLOW_RULE (nanosleep);
    ALLOW_RULE (getdents);
    ALLOW_RULE (fcntl);
    ALLOW_RULE (set_robust_list);
    ALLOW_RULE (clone);
    ALLOW_RULE (recvfrom);
    ALLOW_RULE (sendto);
    ALLOW_RULE (rt_sigprocmask);
    ALLOW_RULE (madvise);
    ALLOW_RULE (exit);
    ALLOW_RULE (socket);
    ALLOW_RULE (fadvise64);
    ALLOW_RULE (geteuid);
    ALLOW_RULE (sigaltstack);
    ALLOW_RULE (statfs);
    ALLOW_RULE (connect);
    ALLOW_RULE (inotify_add_watch);
    ALLOW_RULE (getegid);
    ALLOW_RULE (shmat);
    ALLOW_RULE (shmctl);
    ALLOW_RULE (shmdt);
    ALLOW_RULE (shmget);
    ALLOW_RULE (epoll_wait);
    ALLOW_RULE (gettid);
    ALLOW_RULE (pwrite64);
    ALLOW_RULE (rt_sigreturn);
    ALLOW_RULE (prctl);
    ALLOW_RULE (kill);
    ALLOW_RULE (setsid);
    ALLOW_RULE (listen);
    ALLOW_RULE (capget);
    ALLOW_RULE (accept4);
    ALLOW_RULE (getsockopt);
    ALLOW_RULE (setrlimit);
    ALLOW_RULE (restart_syscall);
    ALLOW_RULE (newfstatat);
    ALLOW_RULE (epoll_ctl);
    ALLOW_RULE (epoll_create1);
    ALLOW_RULE (arch_prctl);
    ALLOW_RULE (bind);
    ALLOW_RULE (chdir);
    ALLOW_RULE (chmod);
    ALLOW_RULE (clock_getres);
    ALLOW_RULE (dup);
    ALLOW_RULE (dup2);
    ALLOW_RULE (execve);
    ALLOW_RULE (exit_group);
    ALLOW_RULE (fallocate);
    ALLOW_RULE (sysinfo);
    ALLOW_RULE (flistxattr);
    ALLOW_RULE (fsync);
    ALLOW_RULE (getgid);
    ALLOW_RULE (getrandom);
    ALLOW_RULE (getcwd);
    ALLOW_RULE (getpeername);
    ALLOW_RULE (getpid);
    ALLOW_RULE (getresgid);
    ALLOW_RULE (getresuid);
    ALLOW_RULE (getrlimit);
    ALLOW_RULE (getrusage);
    ALLOW_RULE (getsockname);
    ALLOW_RULE (getuid);
    ALLOW_RULE (getxattr);
    ALLOW_RULE (inotify_init1);
    ALLOW_RULE (inotify_rm_watch);
    ALLOW_RULE (ioctl);
    ALLOW_RULE (lchown);
    ALLOW_RULE (lgetxattr);
    ALLOW_RULE (link);
    ALLOW_RULE (listxattr);
    ALLOW_RULE (mkdir);
    ALLOW_RULE (mremap);
    ALLOW_RULE (openat);
    ALLOW_RULE (pipe);
    ALLOW_RULE (pipe2);
    ALLOW_RULE (readlink);
    ALLOW_RULE (rename);
    ALLOW_RULE (rmdir);
    ALLOW_RULE (sched_getaffinity);
    ALLOW_RULE (setsockopt);
    ALLOW_RULE (set_tid_address);
    ALLOW_RULE (shutdown);
    ALLOW_RULE (socketpair);
    ALLOW_RULE (splice);
    ALLOW_RULE (tgkill);
    ALLOW_RULE (uname);
    ALLOW_RULE (unlink);
    ALLOW_RULE (utimes);
    ALLOW_RULE (wait4);
    ALLOW_RULE (clock_gettime);
    ALLOW_RULE (gettimeofday);
    ALLOW_RULE (getdents64);
    ALLOW_RULE (prlimit64);
    
    filter_fd = open("/usr/local/share/seccomp/evince_seccomp.bpf", O_CREAT | O_WRONLY, 0644);
    if (filter_fd == -1) {
        rc = -errno;
        goto out;
    }

    rc = seccomp_export_bpf(ctx, filter_fd);
    if (rc < 0) {
        close(filter_fd);
        goto out;
    }
    close(filter_fd);


 out:
    seccomp_release(ctx);
    return -rc;
}
