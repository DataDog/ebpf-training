// +build ignore

#include <linux/in6.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <net/inet_sock.h>
// #include <net/sock.h>
// #include <bcc/proto.h>

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

//    return true;

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
/*
//the structure that will be used as a key for
// eBPF table 'proc_ports':
struct port_key {
    u8 proto;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};
// the structure which will be stored in the eBPF table 'proc_ports',
// contains information about the process:
struct port_val {
    u32 ifindex;
    u32 pid;
    u32 tgid;
    u32 uid;
    u32 gid;
    char comm[64];
};
// Public (accessible from other eBPF programs) eBPF table
// information about the process is written to.
// It is read when a packet appears on the socket:
BPF_TABLE_PUBLIC("hash", struct port_key, struct port_val, proc_ports, 20480);
int trace_udp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    u16 sport = sk->sk_num;
    u16 dport = sk->sk_dport;
  
    // Processing only packets on port 53.
    // 13568 = ntohs(53);
    if (sport == 13568 || dport == 13568) {
        // Preparing the data:
        u32 saddr = sk->sk_rcv_saddr;
        u32 daddr = sk->sk_daddr;
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u64 uid_gid = bpf_get_current_uid_gid();
        // Forming the structure-key.
        struct port_key key = {.proto = 17};
        key.saddr = htonl(saddr);
        key.daddr = htonl(daddr);
        key.sport = sport;
        key.dport = htons(dport);
        //Forming a structure with socket properties:
        struct port_val val = {};
        val.pid = pid_tgid >> 32;
        val.tgid = (u32)pid_tgid;
        val.uid = (u32)uid_gid;
        val.gid = uid_gid >> 32;
        bpf_get_current_comm(val.comm, 64);
        //Write the value into the eBPF table:
        proc_ports.update(&key, &val);
    }
    return 0;
}
int trace_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk) {
    u16 sport = sk->sk_num;
    u16 dport = sk->sk_dport;
  
    // Processing only packets on port 53.
    // 13568 = ntohs(53);
    if (sport == 13568 || dport == 13568) {
        // preparing the data:
        u32 saddr = sk->sk_rcv_saddr;
        u32 daddr = sk->sk_daddr;
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u64 uid_gid = bpf_get_current_uid_gid();
        // Forming the structure-key.
        struct port_key key = {.proto = 6};
        key.saddr = htonl(saddr);
        key.daddr = htonl(daddr);
        key.sport = sport;
        key.dport = htons(dport);
        //Form a structure with socket properties:
        struct port_val val = {};
        val.pid = pid_tgid >> 32;
        val.tgid = (u32)pid_tgid;
        val.uid = (u32)uid_gid;
        val.gid = uid_gid >> 32;
        bpf_get_current_comm(val.comm, 64);
        //Write the value into the eBPF table:
        proc_ports.update(&key, &val);
    }
    return 0;
}

// eBPF table from which information about the process is extracted.
// Filled when calling kernel functions udp_sendmsg()/tcp_sendmsg():
BPF_TABLE("extern", struct port_key, struct port_val, proc_ports, 20480);
// table for transmitting data to the user space:
BPF_PERF_OUTPUT(dns_events);
// Among the data passing through the socket, look for DNS packets
// and check for information about the process:
int dns_matching(struct __sk_buff *skb) {
    u8 *cursor = 0;
    // check the IP protocol:
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    if (ethernet->type == ETH_P_IP) {
        struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
        u8 proto;
        u16 sport;
        u16 dport;
        // We check the transport layer protocol:
        if (ip->nextp == IPPROTO_UDP) {
            struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));
            proto = 17;
            //receive port data:
            sport = udp->sport;
            dport = udp->dport;
        } else if (ip->nextp == IPPROTO_TCP) {
            struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));
            // We don't need packets where no data is transmitted:
            if (!tcp->flag_psh) {
                return 0;
            }
            proto = 6;
            // We get the port data:
            sport = tcp->src_port;
            dport = tcp->dst_port;
        } else {
            return 0;
        }
        // if this is a DNS request:
        if (dport == 53 || sport == 53) {
            // we form the structure-key:
            struct port_key key = {};
            key.proto = proto;
            if (skb->ingress_ifindex == 0) {
                key.saddr = ip->src;
                key.daddr = ip->dst;
                key.sport = sport;
                key.dport = dport;
            } else {
                key.saddr = ip->dst;
                key.daddr = ip->src;
                key.sport = dport;
                key.dport = sport;
            }
            // By the key we are looking for a value in the eBPF table:
            struct port_val *p_val;
            p_val = proc_ports.lookup(&key);
            // If the value is not found, it means that we do not have information about the
            // process, so there is no point in continuing:
            if (!p_val) {
                return 0;
            }
            // network device index:
            p_val->ifindex = skb->ifindex;
            // pass the structure with the process information along with
            // skb->len bytes sent to the socket:
            dns_events.perf_submit_skb(skb, skb->len, p_val,
                                       sizeof(struct port_val));
            return 0;
        } //dport == 53 || sport == 53
    } //ethernet->type == ETH_P_IP
    return 0;
}
*/
