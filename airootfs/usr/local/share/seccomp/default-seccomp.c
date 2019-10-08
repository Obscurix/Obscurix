#include <seccomp.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

/* default seccomp blacklist */

#define DENY_RULE(call) { if (seccomp_rule_add (ctx, SCMP_ACT_KILL, SCMP_SYS(call), 0) < 0) goto out; }

int main(int argc, char *argv[])
{
    int rc = -1;
    scmp_filter_ctx ctx;
    int filter_fd;

    /* for blacklisting */
    
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL)
         goto out;

    DENY_RULE (_sysctl);
    DENY_RULE (acct);
    DENY_RULE (add_key);
    DENY_RULE (adjtimex);
    DENY_RULE (afs_syscall);
    DENY_RULE (bdflush);
    DENY_RULE (bpf);
    DENY_RULE (break);
    DENY_RULE (chroot);
    DENY_RULE (clock_adjtime);
    DENY_RULE (clock_settime);
    DENY_RULE (create_module);
    DENY_RULE (delete_module);
    DENY_RULE (fanotify_init);
    DENY_RULE (finit_module);
    DENY_RULE (ftime);
    DENY_RULE (get_kernel_syms);
    DENY_RULE (getpmsg);
    DENY_RULE (gtty);
    DENY_RULE (init_module);
    DENY_RULE (io_cancel);
    DENY_RULE (io_destroy);
    DENY_RULE (io_getevents);
    DENY_RULE (io_setup);
    DENY_RULE (io_submit);
    DENY_RULE (ioperm);
    DENY_RULE (iopl);
    DENY_RULE (ioprio_set);
    DENY_RULE (kcmp);
    DENY_RULE (kexec_file_load);
    DENY_RULE (kexec_load);
    DENY_RULE (keyctl);
    DENY_RULE (lock);
    DENY_RULE (lookup_dcookie);
    DENY_RULE (mbind);
    DENY_RULE (migrate_pages);
    DENY_RULE (modify_ldt);
    DENY_RULE (mount);
    DENY_RULE (move_pages);
    DENY_RULE (mpx);
    DENY_RULE (name_to_handle_at);
    DENY_RULE (nfsservctl);
    DENY_RULE (open_by_handle_at);
    DENY_RULE (pciconfig_iobase);
    DENY_RULE (pciconfig_read);
    DENY_RULE (pciconfig_write);
    DENY_RULE (perf_event_open);
    DENY_RULE (personality);
    DENY_RULE (pivot_root);
    DENY_RULE (process_vm_readv);
    DENY_RULE (process_vm_writev);
    DENY_RULE (prof);
    DENY_RULE (profil);
    DENY_RULE (ptrace);
    DENY_RULE (putpmsg);
    DENY_RULE (query_module);
    DENY_RULE (reboot);
    DENY_RULE (remap_file_pages);
    DENY_RULE (request_key);
    DENY_RULE (rtas);
    DENY_RULE (s390_runtime_instr);
    DENY_RULE (security);
    DENY_RULE (set_mempolicy);
    DENY_RULE (setdomainname);
    DENY_RULE (sethostname);
    DENY_RULE (settimeofday);
    DENY_RULE (sgetmask);
    DENY_RULE (ssetmask);
    DENY_RULE (stime);
    DENY_RULE (stty);
    DENY_RULE (subpage_prot);
    DENY_RULE (swapoff);
    DENY_RULE (swapon);
    DENY_RULE (switch_endian);
    DENY_RULE (sys_debug_setcontext);
    DENY_RULE (sysfs);
    DENY_RULE (syslog);
    DENY_RULE (tuxcall);
    DENY_RULE (ulimit);
    DENY_RULE (umount);
    DENY_RULE (umount2);
    DENY_RULE (uselib);
    DENY_RULE (userfaultfd);
    DENY_RULE (ustat);
    DENY_RULE (vhangup);
    DENY_RULE (vm86);
    DENY_RULE (vm86old);
    DENY_RULE (vmsplice);
    DENY_RULE (vserver);
    
    filter_fd = open("/usr/local/share/seccomp/default_seccomp.bpf", O_CREAT | O_WRONLY, 0644);
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
