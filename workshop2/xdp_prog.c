// Based on https://github.com/iovisor/gobpf/blob/master/examples/bcc/xdp/xdp_drop.go (2017 GustavoKatel)
// Licensed under the Apache License, Version 2.0 (the "License")

#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

BPF_ARRAY(protocol_counter, long, 256);
const int RETURN_CODE = XDP_PASS;

// Forward declaration
static int parse_ipv4(void *data, void *data_end);
static int parse_ipv6(void *data, void *data_end);

// Main logic starts here

int xdp_counter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    uint64_t network_header_offset = sizeof(*eth);

    if (data + network_header_offset > data_end)
    {
        return RETURN_CODE;
    }

    uint16_t h_proto = eth->h_proto;
    int protocol_index;

    if (h_proto == htons(ETH_P_IP))
    {
        protocol_index = parse_ipv4(data + network_header_offset, data_end);
    }
    else if (h_proto == htons(ETH_P_IPV6))
    {
        protocol_index = parse_ipv6(data + network_header_offset, data_end);
    }
    else
    {
        protocol_index = 0;
    }

    if (protocol_index == 0)
    {
        return RETURN_CODE;
    }

    long *protocol_count = protocol_counter.lookup(&protocol_index);
    if (protocol_count)
    {
        lock_xadd(protocol_count, 1);
    }
    return RETURN_CODE;
}

static inline int parse_ipv4(void *ip_data, void *data_end)
{
    struct iphdr *ip_header = ip_data;
    if ((void *)&ip_header[1] > data_end)
    {
        return 0;
    }
    return ip_header->protocol;
}

static inline int parse_ipv6(void *ipv6_data, void *data_end)
{
    struct ipv6hdr *ip6_header = ipv6_data;
    if ((void *)&ip6_header[1] > data_end)
    {
        return 0;
    }
    return ip6_header->nexthdr;
}
