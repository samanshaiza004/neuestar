// H0.1S adversarial child: user-controlled code executed through the trusted
// helper. Actively attempts nested userns + mount + pivot_root setup.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>

static int try_unshare(void) {
    if (unshare(CLONE_NEWUSER) == 0) {
        // inside a new userns, try to write uid_map as the owner
        int fd = open("/proc/self/uid_map", O_WRONLY);
        if (fd >= 0) {
            int rc = write(fd, "0 1000 1\n", 9);
            close(fd);
            return rc >= 0 ? 1 : 2; // 1 = mapped, 2 = userns ok but map denied
        }
        return 3; // userns ok, no uid_map file
    }
    return 0; // EPERM
}

static int try_mount(void) {
    return mount("none", "/", "none", MS_REC | MS_PRIVATE, NULL) == 0 ? 1 : 0;
}

static int try_pivot(void) {
    char old[64];
    if (mkdir("/tmp/pivot-old", 0700) != 0 && errno != EEXIST) return 0;
    if (mkdir("/tmp/pivot-new", 0700) != 0 && errno != EEXIST) return 0;
    if (syscall(SYS_pivot_root, "/tmp/pivot-new", "/tmp/pivot-old") == 0) return 1;
    return 0;
}

int main(void) {
    int u = try_unshare();
    int m = try_mount();
    int p = try_pivot();
    printf("adversarial_child: unshare_ns=%d mount=%d pivot=%d\n", u, m, p);
    fflush(stdout);
    // exit 0 if ALL denied (safe), 1 if any setup succeeded
    return (u == 0 && m == 0 && p == 0) ? 0 : 1;
}
