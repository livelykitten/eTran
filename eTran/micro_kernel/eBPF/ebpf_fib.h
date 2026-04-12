/**
 * @file ebpf_fib.h
 * @brief eBPF FIB lookup program
 * eBPF program calls fib_lookup() to perform a FIB lookup
 * eBPF program must provide valid iph->saddr, iph->daddr, and ctx->ingress_ifindex
 * A per-cpu LRU hash table serves as a FIB cache to accelerate the lookup
 */
#pragma once
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>

#include "ebpf_utils.h"

#define MAX_FIB_CACHE_SIZE 1024

struct dst_entry {
    __u8 valid;
    __u8 smac[ETH_ALEN];
    __u8 dmac[ETH_ALEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, MAX_FIB_CACHE_SIZE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct dst_entry));
    __uint(map_flags, BPF_F_NO_COMMON_LRU);
} fib_cache_map SEC(".maps");

static __always_inline int find_dst_entry_in_cache(struct iphdr *iph, struct ethhdr *eth)
{
    __u32 ipv4_dst = iph->daddr;
    struct dst_entry *dst_entry = bpf_map_lookup_elem(&fib_cache_map, &ipv4_dst);
    if (unlikely(!dst_entry || dst_entry->valid == 0))
        return -1;
    __builtin_memcpy(eth->h_dest, dst_entry->dmac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, dst_entry->smac, ETH_ALEN);
    eth->h_proto = bpf_htons(ETH_P_IP);
    return 0;
}

static __always_inline int update_dst_entry_in_cache(struct iphdr *iph, struct ethhdr *eth)
{
    __u32 ipv4_dst = iph->daddr;
    struct dst_entry new_dst_entry = {0};
    new_dst_entry.valid = 1;
    __builtin_memcpy(new_dst_entry.smac, eth->h_source, ETH_ALEN);
    __builtin_memcpy(new_dst_entry.dmac, eth->h_dest, ETH_ALEN);
    return bpf_map_update_elem(&fib_cache_map, &ipv4_dst, &new_dst_entry, BPF_ANY);
}

static __always_inline void set_fib_params(struct bpf_fib_lookup *fib_params, struct iphdr *iph, int ifindex)
{
    fib_params->family = AF_INET;
    fib_params->tos = iph->tos;
    fib_params->tot_len = bpf_ntohs(iph->tot_len);
    fib_params->ipv4_src = iph->saddr;
    fib_params->ipv4_dst = iph->daddr;
    fib_params->ifindex = ifindex;
}

static __always_inline void set_ethhdr(struct ethhdr *eth, struct bpf_fib_lookup *fib_params)
{
    __builtin_memcpy(eth->h_dest, fib_params->dmac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, fib_params->smac, ETH_ALEN);
    eth->h_proto = bpf_htons(ETH_P_IP);
}

static __always_inline int fib_lookup(struct xdp_md *ctx, struct ethhdr *eth, struct iphdr *iph)
{
    // xdp_log("fib_lookup() called");
    // xdp_egress_log("56778");
    // xdp_log_err("12344444444");
    // xdp_egress_log_err("567788888888");
    int ret = find_dst_entry_in_cache(iph, eth);
    // xdp_log("ret of find_dst_entry_in_cache(): %d", ret);
    // xdp_log("cache hit, src: %pM, dst: %pM, proto: %d", eth->h_source, eth->h_dest, eth->h_proto);
    // xdp_log("src mac %02x:%02x:%02x:%02x:%02x:%02x",
    // eth->h_source[0], eth->h_source[1], eth->h_source[2],
    // eth->h_source[3], eth->h_source[4], eth->h_source[5]);

    // xdp_log("dst mac %02x:%02x:%02x:%02x:%02x:%02x",
    // eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
    // eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    if (likely(ret == 0)) {
        /* cache hit */
        return 0;
    }

    struct bpf_fib_lookup fib_params = {0};
    // xdp_log("ctx->ingress_ifindex: %d", ctx->ingress_ifindex);
    // xdp_log("ctx->egress_ifindex: %d\n", ctx->egress_ifindex);
    set_fib_params(&fib_params, iph, ctx->ingress_ifindex);
    int fib_rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
    if (unlikely(fib_rc != BPF_FIB_LKUP_RET_SUCCESS)) {
        xdp_log_err("FIB lookup failed: %d 1234", fib_rc);
        xdp_egress_log_err("FIB lookup failed: %d", fib_rc);
        return -1;
    }


    // xdp_log("lookup finished. src mac: %pM", fib_params.smac);
    // xdp_log("lookup finished. dst mac: %pM", fib_params.dmac);
        
    /* Fill ethernet header */
    set_ethhdr(eth, &fib_params);
    
    /* update cache */
    ret = update_dst_entry_in_cache(iph, eth);
    if (ret) {
        xdp_log_err("update_dst_entry_in_cache() failed: %d by log_err", ret);
        xdp_egress_log_err("update_dst_entry_in_cache() failed: %d", ret);
    }
    // xdp_log("ret: %d", ret);
    return ret;
}

static __always_inline int xmit_packet(struct xdp_md *ctx, struct ethhdr *eth, struct iphdr *iph)
{
    int err = fib_lookup(ctx, eth, iph);
    if (unlikely(err)) {
        log_err("bpf_fib_lookup failed, check routing table in kernel.");
    }
    return XDP_TX;
}