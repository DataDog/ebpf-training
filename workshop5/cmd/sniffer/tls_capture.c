// +build ignore

#include <uapi/linux/ptrace.h>

#define MAX_SIZE 400

struct tls_data_args_t {
    const char* buf;
};

struct tls_ex_data_args_t {
    const char* buf;
    size_t *buf_size;
};

enum traffic_direction_t {
    kEgress,
    kIngress,
};

struct data_event_t {
    uint64_t timestamp_ns;
    uint32_t pid;
    enum traffic_direction_t direction;
    char msg [MAX_SIZE];
};

BPF_HASH(tls_write_args_map, uint64_t, struct tls_data_args_t);
BPF_HASH(tls_read_args_map, uint64_t, struct tls_data_args_t);

BPF_HASH(tls_write_ex_args_map, uint64_t, struct tls_ex_data_args_t);
BPF_HASH(tls_read_ex_args_map, uint64_t, struct tls_ex_data_args_t);

BPF_PERF_OUTPUT(data_events);

BPF_PERCPU_ARRAY(pid, int, 1);

static inline void process_data(struct pt_regs* ctx, uint64_t id, size_t bytes_count, enum traffic_direction_t direction, const char* buf) {
    if (buf == NULL) {
        return;
    }

    int return_code = PT_REGS_RC(ctx);
    if (return_code <= 0) {
        return;
    }

    int key = 0;
    int *pidToAllow = pid.lookup(&key);
    if (pidToAllow != NULL && *pidToAllow != -1) {
        bpf_trace_printk("%d\n", *pidToAllow);
        const int current_pid = id >> 32;
        if (current_pid != *pidToAllow) {
            return;
        }
    }

    struct data_event_t event = {};
    event.timestamp_ns = bpf_ktime_get_ns();
    event.direction = direction;
    event.pid = id >> 32;
    size_t msg_size = bytes_count < MAX_SIZE ? bytes_count : MAX_SIZE;
    bpf_probe_read(&event.msg, msg_size, buf);
    data_events.perf_submit(ctx, &event, sizeof(struct data_event_t));
}

int probe_entry_ssl_read(struct pt_regs *ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    struct tls_data_args_t read_args = {};
    read_args.buf = (char*)PT_REGS_PARM2(ctx);
    tls_read_args_map.update(&id, &read_args);
    return 0;
}

int probe_ret_ssl_read(struct pt_regs *ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    struct tls_data_args_t* read_args = tls_read_args_map.lookup(&id);
    if (read_args != NULL) {
        tls_read_args_map.delete(&id);

        process_data(ctx, id, PT_REGS_RC(ctx), kIngress, read_args->buf);
    }

    return 0;
}

int probe_entry_ssl_write(struct pt_regs *ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    struct tls_data_args_t write_args = {};
    write_args.buf = (const char *) PT_REGS_PARM2(ctx);

    tls_write_args_map.update(&id, &write_args);
    return 0;
}

int probe_ret_ssl_write(struct pt_regs *ctx) {
    uint64_t id = bpf_get_current_pid_tgid();

    struct tls_data_args_t* write_args = tls_write_args_map.lookup(&id);
    if (write_args != NULL) {
        tls_write_args_map.delete(&id);

        process_data(ctx, id, PT_REGS_RC(ctx), kEgress, write_args->buf);
    }

    return 0;
}

int probe_entry_ssl_read_ex(struct pt_regs *ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    struct tls_ex_data_args_t read_args = {};
    read_args.buf = (char*)PT_REGS_PARM2(ctx);
    read_args.buf_size = (size_t*)PT_REGS_PARM4(ctx);

    tls_read_ex_args_map.update(&id, &read_args);
    return 0;
}

int probe_ret_ssl_read_ex(struct pt_regs *ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    struct tls_ex_data_args_t* read_args = tls_read_ex_args_map.lookup(&id);
    if (read_args != NULL) {
        tls_read_ex_args_map.delete(&id);

        size_t bytes_count = 0;
        bpf_probe_read_user(&bytes_count, sizeof(bytes_count), read_args->buf_size);
        process_data(ctx, id, bytes_count, kIngress, read_args->buf);
    }

    return 0;
}

int probe_entry_ssl_write_ex(struct pt_regs *ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    struct tls_ex_data_args_t write_args = {};
    write_args.buf = (const char *)PT_REGS_PARM2(ctx);
    write_args.buf_size = (size_t*)PT_REGS_PARM4(ctx);

    tls_write_ex_args_map.update(&id, &write_args);
    return 0;
}

int probe_ret_ssl_write_ex(struct pt_regs *ctx) {
    uint64_t id = bpf_get_current_pid_tgid();

    struct tls_ex_data_args_t* write_args = tls_write_ex_args_map.lookup(&id);
    if (write_args != NULL) {
        tls_write_ex_args_map.delete(&id);

        size_t bytes_count = 0;
        bpf_probe_read_user(&bytes_count, sizeof(bytes_count), write_args->buf_size);
        process_data(ctx, id, bytes_count, kEgress, write_args->buf);
    }

    return 0;
}