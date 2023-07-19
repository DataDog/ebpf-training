#!/usr/bin/env python3

from struct import unpack
from bcc import BPF
from socket import if_indextoname


C_BPF_KPROBE = """
#include <net/sock.h>

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
"""


BPF_SOCK_TEXT = r'''
#include <net/sock.h>
#include <bcc/proto.h>

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
'''


try:
    import dnslib
except ImportError:
    print("Error: Python dnslib module required.")
    print("Install it with:")
    print("\t$ pip3 install dnslib")
    print(" or")
    print("\t$ sudo apt install python3-dnslib (on Ubuntu 20+)")
    exit(1)


def print_dns(cpu, data, size):
    import ctypes as ct
    class SkbEvent(ct.Structure):
        _fields_ = [
            ("ifindex", ct.c_uint32),
            ("pid", ct.c_uint32),
            ("tgid", ct.c_uint32),
            ("uid", ct.c_uint32),
            ("gid", ct.c_uint32),
            ("comm", ct.c_char * 64),
            ("raw", ct.c_ubyte * (size - ct.sizeof(ct.c_uint32 * 5) - ct.sizeof(ct.c_char * 64)))
        ]
    # We get our 'port_val' structure and also the packet itself in the 'raw' field:
    sk = ct.cast(data, ct.POINTER(SkbEvent)).contents

    # Protocols:
    NET_PROTO = {6: "TCP", 17: "UDP"}

    # eBPF operates on thread names.
    # Sometimes they are the same as the process names, but often they are not.
    # So we try to get the process name by its PID:
    try:
        with open(f'/proc/{sk.pid}/comm', 'r') as proc_comm:


            proc_name = proc_comm.read().rstrip()
    except:
        proc_name = sk.comm.decode()

    # Get the name of the network interface by index:
    ifname = if_indextoname(sk.ifindex)

    # The length of the Ethernet frame header is 14 bytes:
    ip_packet = bytes(sk.raw[14:])

    # The length of the IP packet header is not fixed due to the arbitrary
    # number of parameters.
    # Of all the possible IP header we are only interested in 20 bytes:
    (length, _, _, _, _, proto, _, saddr, daddr) = unpack('!BBHLBBHLL', ip_packet[:20])
    # The direct length is written in the second half of the first byte (0b00001111 = 15):
    len_iph = length & 15
    # Length is written in 32-bit words, convert it to bytes:
    len_iph = len_iph * 4
    # Convert addresses from numbers to IPs:
    saddr = ".".join(map(str, [saddr >> 24 & 0xff, saddr >> 16 & 0xff, saddr >> 8 & 0xff, saddr & 0xff]))
    daddr = ".".join(map(str, [daddr >> 24 & 0xff, daddr >> 16 & 0xff, daddr >> 8 & 0xff, daddr & 0xff]))

    # If the transport layer protocol is UDP:
    if proto == 17:
        udp_packet = ip_packet[len_iph:]
        (sport, dport) = unpack('!HH', udp_packet[:4])
        # UDP datagram header length is 8 bytes:
        dns_packet = udp_packet[8:]
    # If the transport layer protocol is TCP:
    elif proto == 6:
        tcp_packet = ip_packet[len_iph:]
        # The length of the TCP packet header is also not fixed due to the optional options.
        # Of the entire TCP header we are only interested in the data up to the 13th byte
        # (header length):
        (sport, dport, _, length) = unpack('!HHQB', tcp_packet[:13])
        # The direct length is written in the first half (4 bits):
        len_tcph = length >> 4
        # Length is written in 32-bit words, converted to bytes:
        len_tcph = len_tcph * 4
        # That's the tricky part.
        # I don't know where I went wrong or why I need a 2 byte offset,
        # but it's necessary because the DNS packet doesn't start until after it:
        dns_packet = tcp_packet[len_tcph + 2:]
    # other protocols are not handled:
    else:
        return

    # DNS data decoding:
    dns_data = dnslib.DNSRecord.parse(dns_packet)

    # Resource record types:
    DNS_QTYPE = {1: "A", 28: "AAAA"}

    # Query:
    if dns_data.header.qr == 0:
        # We are only interested in A (1) and AAAA (28) records:
        for q in dns_data.questions:
            if q.qtype == 1 or q.qtype == 28:
                print(f'COMM={proc_name} PID={sk.pid} TGID={sk.tgid} DEV={ifname} PROTO={NET_PROTO[proto]} SRC={saddr} DST={daddr} SPT={sport} DPT={dport} UID={sk.uid} GID={sk.gid} DNS_QR=0 DNS_NAME={q.qname} DNS_TYPE={DNS_QTYPE[q.qtype]}')
    # Response:
    elif dns_data.header.qr == 1:
        # We are only interested in A (1) and AAAA (28) records:
        for rr in dns_data.rr:
            if rr.rtype == 1 or rr.rtype == 28:
                print(f'COMM={proc_name} PID={sk.pid} TGID={sk.tgid} DEV={ifname} PROTO={NET_PROTO[proto]} SRC={saddr} DST={daddr} SPT={sport} DPT={dport} UID={sk.uid} GID={sk.gid} DNS_QR=1 DNS_NAME={rr.rname} DNS_TYPE={DNS_QTYPE[rr.rtype]} DNS_DATA={rr.rdata}')
    else:
        print('Invalid DNS query type.')

# BPF initialization:
bpf_kprobe = BPF(text=C_BPF_KPROBE)
bpf_sock = BPF(text=BPF_SOCK_TEXT)

# UDP sending:
bpf_kprobe.attach_kprobe(event="udp_sendmsg", fn_name="trace_udp_sendmsg")

# Sending TCP:
bpf_kprobe.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_sendmsg")

# Socket:
function_dns_matching = bpf_sock.load_func("dns_matching", BPF.SOCKET_FILTER)
BPF.attach_raw_socket(function_dns_matching, '')

print('The program is running. Press Ctrl-C to abort.')

bpf_sock["dns_events"].open_perf_buffer(print_dns)

while True:
    try:
        bpf_sock.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()