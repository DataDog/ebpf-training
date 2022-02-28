// +build ignore

#include <uapi/linux/ptrace.h>

#define MAX_SIZE 255

enum event_type_t {
    kOpenEvent = 0,
    kDeniedEvent = 1,
};

struct open_event_t {
    uint64_t timestamp_ns;
    uint32_t pid;
    int32_t return_code;
    enum event_type_t event_type;
    char copiedPath [MAX_SIZE];
};

BPF_PERF_OUTPUT(open_events);
BPF_PERF_OUTPUT(denied_events);
BPF_HASH(open_event_args, uint64_t, struct open_event_t);
BPF_PERCPU_ARRAY(pid, int, 1);

int syscall__probe_entry_openat(struct pt_regs* ctx, int dirfd, const char *pathname, int flags) {
    if (pathname == NULL) {
        return 0;
    }

    struct open_event_t event = {};
    bpf_probe_read_user_str(event.copiedPath, MAX_SIZE, pathname);

    int actualSize = 0;
    for (; actualSize < MAX_SIZE; actualSize++) {
        if (event.copiedPath[actualSize] == '\0') {
            break;
        }
    }

    char secret_file [] = "sensitive.key";
    if (actualSize < sizeof(secret_file) - 1) {
        return 0;
    }

    for (size_t offset = 1; offset < sizeof(secret_file); offset++) {
        if (event.copiedPath[actualSize - offset] != secret_file[sizeof(secret_file) - 1 - offset]) {
            return 0;
        }
    }

    uint64_t id = bpf_get_current_pid_tgid();
    event.timestamp_ns = bpf_ktime_get_ns();
    event.event_type = kOpenEvent;
    event.pid = id >> 32;

    open_event_args.update(&id, &event);

    return 0;
}

int syscall__probe_ret_openat(struct pt_regs* ctx) {
    int64_t id = bpf_get_current_pid_tgid();

    struct open_event_t* open_args = open_event_args.lookup(&id);
    if (open_args != NULL) {
        open_args->return_code = (int32_t)PT_REGS_RC(ctx);
        open_events.perf_submit(ctx, open_args, sizeof(struct open_event_t));
        open_event_args.delete(&id);
    }

    return 0;
}

int syscall__probe_ret_openat_deny(struct pt_regs* ctx) {
    int64_t id = bpf_get_current_pid_tgid();

    struct open_event_t* open_args = open_event_args.lookup(&id);
    if (open_args != NULL) {
        int key = 0;
        int *pidToAllow = pid.lookup(&key);
        if (pidToAllow != NULL) {
            const int current_pid = id >> 32;
            if (current_pid != *pidToAllow) {
                open_args->event_type = kDeniedEvent;
                bpf_override_return(ctx, -13);
            }
        }
        open_args->return_code = (int32_t)PT_REGS_RC(ctx);
        open_events.perf_submit(ctx, open_args, sizeof(struct open_event_t));
        open_event_args.delete(&id);
    }

    return 0;
}