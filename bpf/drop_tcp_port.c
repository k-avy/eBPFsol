#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

struct bpf_map_def {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u16));
} port_map SEC(".maps");

SEC("prog")
int drop_tcp_port(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    __u32 key = 0;
    __u16 *port;

    if ((void *)(eth + 1) > data_end - sizeof(*eth))
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end - sizeof(*ip))
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    tcp = (struct tcphdr *)(ip + 1);
    if ((void *)(tcp + 1) > data_end - sizeof(*tcp))
        return XDP_PASS;

    port = bpf_map_lookup_elem(&port_map, &key);
    if (port && tcp->dest == __constant_htons(*port))
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
