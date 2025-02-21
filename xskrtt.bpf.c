// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "xskrtt.h"

#define ETH_P_IPV6 0x86DD

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} xsk SEC(".maps");

int port;

extern int bpf_xdp_metadata_rx_timestamp(const struct xdp_md *ctx,
					 __u64 *timestamp) __ksym;

SEC("xdp.frags")
int rx(struct xdp_md *ctx)
{
	return XDP_PASS;
	/*void *data, *data_meta, *data_end;
	struct xdp_meta *meta;
	struct ipv6hdr *ip6h;
	struct udphdr *udp;
	struct ethhdr *eth;
	struct iphdr *iph;
	struct payload *p;
	__u64 hw_tstamp;
	__u64 sw_tstamp;
	int err;

	sw_tstamp = bpf_ktime_get_tai_ns();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	eth = data;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	if (eth->h_proto != bpf_htons(ETH_P_IPV6))
		return XDP_PASS;

	ip6h = (void *)(eth + 1);

	if ((void *)(ip6h + 1) > data_end)
		return XDP_PASS;

	if (ip6h->nexthdr != IPPROTO_UDP)
		return XDP_PASS;

	udp = (void *)(ip6h + 1);

	if ((void *)(udp + 1) > data_end)
		return XDP_PASS;

	if (udp->dest != bpf_htons(port))
		return XDP_PASS;

	p = (void *)(udp + 1);

	if ((void *)(p + 1) > data_end)
		return XDP_PASS;

	hw_tstamp = 0;
	bpf_xdp_metadata_rx_timestamp(ctx, &hw_tstamp);
	p->xdp_hw_tstamp = hw_tstamp;
	p->xdp_sw_tstamp = sw_tstamp;

	return bpf_redirect_map(&xsk, 0, XDP_PASS);*/
}

char _license[] SEC("license") = "GPL";
