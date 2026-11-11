/*
 * Fixed privileged entry point. In a guest or explicitly owner-opted-in native
 * mode, sudoers allows iosbroker to run this
 * binary as root with no arguments. It sets a 6 GB jetsam cap on its own
 * pid, permanently becomes iosagent, and execs the worker. It does not
 * read stdin, the environment, or argv beyond rejecting extra arguments.
 *
 * 6144 MB matches containment.MEMORY_LIMIT.
 */
#include <grp.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

struct memorystatus_memlimit_properties {
    int32_t memlimit_active;
    uint32_t memlimit_active_attr;
    int32_t memlimit_inactive;
    uint32_t memlimit_inactive_attr;
};

int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize);

static void close_extra_descriptors(void) {
    int limit = getdtablesize();
    for (int fd = 3; fd < limit; ++fd) {
        (void)close(fd);
    }
}

static void lower_rlimit(int which, rlim_t value) {
    struct rlimit limit;
    limit.rlim_cur = value;
    limit.rlim_max = value;
    (void)setrlimit(which, &limit);
}

static void fail(int code) {
    static const char message[] = "worker_cap refused\n";
    (void)write(STDERR_FILENO, message, sizeof(message) - 1);
    _exit(code);
}

int main(int argc, char **argv) {
    struct memorystatus_memlimit_properties props;
    struct passwd *account;
    char *const arguments[] = {
        "/usr/bin/python3",
        "-I",
        "/Library/ios-worker/worker_exec.py",
        NULL,
    };
    char *const environment[] = {
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME=/Users/iosagent",
        "USER=iosagent",
        "LOGNAME=iosagent",
        "PYTHONNOUSERSITE=1",
        "PYTHONDONTWRITEBYTECODE=1",
        "TMPDIR=/Library/ios-worker/data/tmp",
        "LANG=C",
        NULL,
    };

    if (argc != 1 || argv == NULL || argv[0] == NULL) {
        fail(2);
    }
    if (geteuid() != 0) {
        fail(3);
    }

    /* Address-space rlimits cannot be lowered on this macOS, even as root.
     * The process count can, and children inherit it. Jetsam below is per-pid
     * and is not inherited by xcodebuild's compiler processes.
     */
    lower_rlimit(RLIMIT_NPROC, 512);

    memset(&props, 0, sizeof(props));
    props.memlimit_active = 6144;
    props.memlimit_inactive = 6144;
    /* MEMORYSTATUS_MEMLIMIT_ATTR_FATAL: exceeding the cap kills the process. */
    props.memlimit_active_attr = 0x1;
    props.memlimit_inactive_attr = 0x1;
    (void)memorystatus_control(7, (int32_t)getpid(), 0, &props, sizeof(props));

    account = getpwnam("iosagent");
    if (account == NULL || account->pw_uid == 0) {
        fail(4);
    }
    if (chdir("/tmp") != 0) {
        fail(5);
    }
    if (initgroups(account->pw_name, account->pw_gid) != 0) {
        fail(6);
    }
    if (setgid(account->pw_gid) != 0) {
        fail(7);
    }
    if (setuid(account->pw_uid) != 0) {
        fail(8);
    }
    if (geteuid() != account->pw_uid || getuid() != account->pw_uid) {
        fail(9);
    }

    close_extra_descriptors();
    execve(arguments[0], arguments, environment);
    fail(10);
}
