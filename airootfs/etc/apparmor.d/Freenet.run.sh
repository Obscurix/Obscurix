#include <tunables/global>

/home/freenet/Freenet/run.sh flags=(attach_disconnected) {
  #include <abstractions/base>
  #include <abstractions/bash>

  # For some reason, Freenet asks for read access to nearly
  # every single directory but this isn't actually needed.
  deny / r,
  deny /boot/ r,
  deny /dev/ r,
  deny /etc/ r,
  deny /mnt/ r,
  deny /opt/ r,
  deny /proc/ r,
  deny /root/ r,
  deny /run/ r,
  deny /srv/ r,
  deny /sys/ r,
  deny /tmp/ r,
  deny /usr/ r,
  deny /usr/bin/ r,
  deny /usr/lib/ r,
  deny /var/ r,
  deny /persistent_ARCH_*/x86_64/upperdir/ r,

  /dev/tty rw,

  /etc/host.conf r,
  /etc/hosts r,
  /etc/nsswitch.conf r,
  /etc/passwd r,
  /etc/resolv.conf r,

  /sys/fs/cgroup/cpu,cpuacct/cpu.cfs_period_us r,
  /sys/fs/cgroup/cpu,cpuacct/cpu.cfs_quota_us r,
  /sys/fs/cgroup/cpu,cpuacct/cpu.shares r,
  /sys/fs/cgroup/memory/system.slice/freenet.service/memory.limit_in_bytes r,
  /sys/fs/cgroup/memory/system.slice/freenet.service/memory.use_hierarchy r,

  /{,usr/}bin/java mrix,
  /usr/bin/bash ix,
  /usr/bin/cat mrix,
  /usr/bin/cut mrix,
  /usr/bin/dirname mrix,
  /usr/bin/grep mrix,
  /usr/bin/head mrix,
  /usr/bin/id mrix,
  /usr/bin/ldconfig mrix,
  /usr/bin/mv mrix,
  /usr/bin/nice mrix,
  /usr/bin/rm mrix,
  /usr/bin/sed mrix,
  /usr/bin/tr mrix,
  /usr/bin/uname mrix,
  /usr/bin/which mrix,

  /usr/lib/jvm/java-*-openjdk/** mrix,
  /etc/java-openjdk/** r,
 
  owner /home/freenet/ r,
  owner /home/freenet/Freenet/ r,
  owner /home/freenet/Freenet/** mrwk,
  /home/freenet/Freenet/./bin/wrapper-linux-x86-64 mrix,
  /home/freenet/Freenet/bin/wrapper-linux-x86-64 mrix,
  owner /persistent_ARCH_*/x86_64/upperdir/home/freenet/Freenet/ r,
  owner /persistent_ARCH_*/x86_64/upperdir/home/freenet/Freenet/** r,
 
  owner @{PROC}/@{pid}/cgroup r,
  owner @{PROC}/@{pid}/coredump_filter rw,
  owner @{PROC}/@{pid}/fd/ r,
  owner @{PROC}/@{pid}/mountinfo r,
  owner @{PROC}/@{pid}/stat r,
 
  owner /tmp/hsperfdata_freenet/ rw,
  owner /tmp/hsperfdata_freenet/* rw,
  owner /tmp/wrapper-*-*-* rw,
}
