// +build ignore

#include <linux/in6.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <net/inet_sock.h>

union sockaddr_t {
    struct sockaddr sa;
    struct sockaddr_in in4;
    struct sockaddr_in6 in6;
};

struct accept_args_t {
    union sockaddr_t* addr;
};

struct conn_id_t {
    uint32_t pid;
    int32_t fd;
};

struct socket_open_event_t {
    uint64_t timestamp_ns;
    struct conn_id_t conn_id;
    union sockaddr_t addr;
};

struct data_args_t {
    int32_t fd;
    char* buf;
};

enum traffic_direction_t {
    kEgress,
    kIngress,
};

#define DATA_LEN 400

struct socket_data_event_t {
    uint64_t timestamp_ns;
    struct conn_id_t conn_id;
    enum traffic_direction_t direction;
    uint32_t msg_size;
    char msg[DATA_LEN];
};

struct close_args_t {
    int32_t fd;
};

struct socket_close_event_t {
    uint64_t timestamp_ns;
    struct conn_id_t conn_id;
};

BPF_HASH(active_accept_args_map, uint64_t, struct accept_args_t);
BPF_PERF_OUTPUT(socket_open_events);

BPF_HASH(active_read_args_map, uint64_t, struct data_args_t);
BPF_HASH(active_write_args_map, uint64_t, struct data_args_t);
BPF_PERF_OUTPUT(socket_data_events);

BPF_HASH(active_close_args_map, uint64_t, struct close_args_t);
BPF_PERF_OUTPUT(socket_close_events);

static __inline struct conn_id_t create_conn_id(uint64_t id, int fd) {
    struct conn_id_t conn_id = {};
    uint32_t pid = id >> 32;
    conn_id.pid = pid;
    conn_id.fd = fd;
    return conn_id;
}

static __inline void process_syscall_accept(struct pt_regs* ctx, uint64_t id, const struct accept_args_t* args) {
    int ret_fd = PT_REGS_RC(ctx);
    if (ret_fd <= 0) {
        return;
    }

	struct socket_open_event_t open_event = {};
	open_event.timestamp_ns = bpf_ktime_get_ns();
	open_event.conn_id = create_conn_id(id, ret_fd);
	bpf_probe_read(&open_event.addr, sizeof(open_event.addr), args->addr);

    socket_open_events.perf_submit(ctx, &open_event, sizeof(struct socket_open_event_t));
}

static inline bool is_http_connection(const char* buf, size_t count) {
    if (count < 16) {
        return false;
    }

    if (buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'P') {
        return true;
    }

    if (buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T') {
        return true;
    }

    return false;
}

static inline void process_data(struct pt_regs* ctx, uint64_t id, enum traffic_direction_t direction,
                                const struct data_args_t* args) {
    // Always check access to pointer before accessing them.
    if (args->buf == NULL) {
        return;
    }

    int return_code = PT_REGS_RC(ctx);
    if (return_code <= 0) {
        return;
    }

    size_t bytes_count = return_code;

    // Check if the connection is already HTTP, or check if that's a new connection, check protocol and return true if that's HTTP.
    if (is_http_connection(args->buf, bytes_count)) {
        struct socket_data_event_t event = {};
        // Fill the metadata of the data event.
        event.timestamp_ns = bpf_ktime_get_ns();
        event.direction = direction;
        event.conn_id = create_conn_id(id, args->fd);
        event.msg_size = bytes_count < DATA_LEN ? bytes_count : DATA_LEN;
        bpf_probe_read(&event.msg, event.msg_size, args->buf);
        socket_data_events.perf_submit(ctx, &event, sizeof(struct socket_data_event_t));
    }
}

static inline void process_syscall_close(struct pt_regs* ctx, uint64_t id, int fd) {
    int ret_val = PT_REGS_RC(ctx);
    if (ret_val < 0) {
        return;
    }

    // Send to the user mode an event indicating the connection was closed.
    struct socket_close_event_t close_event = {};
    close_event.timestamp_ns = bpf_ktime_get_ns();
    close_event.conn_id = create_conn_id(id, fd);

    socket_close_events.perf_submit(ctx, &close_event, sizeof(struct socket_close_event_t));
}

int syscall__probe_entry_accept4(struct pt_regs* ctx, int sockfd, struct sockaddr *addr, size_t *addrlen, int flags) {
    int64_t id = bpf_get_current_pid_tgid();

    struct accept_args_t accept_args = {};
    accept_args.addr = (union sockaddr_t*)addr;

    active_accept_args_map.update(&id, &accept_args);
    return 0;
}

int syscall__probe_ret_accept4(struct pt_regs* ctx) {
    int64_t id = bpf_get_current_pid_tgid();

    struct accept_args_t* accept_args = active_accept_args_map.lookup(&id);
    if (accept_args != NULL) {
        process_syscall_accept(ctx, id, accept_args);
        active_accept_args_map.delete(&id);
    }

    return 0;
}

int syscall__probe_entry_read(struct pt_regs* ctx, int fd, char* buf, size_t count) {
    uint64_t id = bpf_get_current_pid_tgid();

    struct data_args_t read_args = {};
    read_args.fd = fd;
    read_args.buf = buf;
    active_read_args_map.update(&id, &read_args);

    return 0;
}

int syscall__probe_ret_read(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();

    struct data_args_t* read_args = active_read_args_map.lookup(&id);
    if (read_args != NULL) {
        process_data(ctx, id, kIngress, read_args);
        active_read_args_map.delete(&id);
    }

    return 0;
}

int syscall__probe_entry_write(struct pt_regs* ctx, int fd, char* buf, size_t count) {
    uint64_t id = bpf_get_current_pid_tgid();

    struct data_args_t write_args = {};
    write_args.fd = fd;
    write_args.buf = buf;
    active_write_args_map.update(&id, &write_args);

    return 0;
}

int syscall__probe_ret_write(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();

    struct data_args_t* write_args = active_write_args_map.lookup(&id);
    if (write_args != NULL) {
        process_data(ctx, id, kEgress, write_args);
        active_write_args_map.delete(&id);
    }

    return 0;
}

int syscall__probe_entry_close(struct pt_regs* ctx, int fd) {
    uint64_t id = bpf_get_current_pid_tgid();
    struct close_args_t close_args;
    close_args.fd = fd;
    active_close_args_map.update(&id, &close_args);

    return 0;
}

int syscall__probe_ret_close(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    const struct close_args_t* close_args = active_close_args_map.lookup(&id);
    if (close_args != NULL) {
        process_syscall_close(ctx, id, close_args->fd);
        active_close_args_map.delete(&id);
    }
    return 0;
}
