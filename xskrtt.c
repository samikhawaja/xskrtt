// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <error.h>
#include <errno.h>
#include <libgen.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#include <linux/ethtool_netlink.h>

#include <bpf/bpf.h>

#include "csum.h"
#include "xsk.h"
#include "xsk_uapi.h"
#include "xskrtt.h"
#include "xskrtt.skel.h"

#ifndef BPF_F_XDP_DEV_BOUND_ONLY
#define BPF_F_XDP_DEV_BOUND_ONLY (1U << 6)
#endif

#ifndef XDP_UMEM_TX_METADATA_LEN
#define XDP_UMEM_TX_METADATA_LEN (1 << 2)
#endif

#define XDP_FLAGS (XDP_FLAGS_DRV_MODE | XDP_FLAGS_REPLACE)

#define UMEM_FRAME_SIZE		4096 /* PAGE_SIZE */

#define NSEC_PER_SEC		1000000000ULL

static bool debug;
static bool offload_tx_csum;
static bool prefill_headers;
static bool ignore_csum;
static bool busy_poll;
static int payload_len = sizeof(struct payload);
static __u32 ring_size = 1024;
static int umem_size = 2048;
static bool use_need_wakeup;
static bool threaded_poll;
static bool scheduled_time;
static bool use_hwtstamp = false;
static bool use_flowsteering = false;
static int affinity = -1;
static bool plain;

struct xsk {
	int fd;
	void *umem_area;

	struct xsk_umem *umem;
	struct xsk_ring_prod fill;
	struct xsk_ring_cons comp;
	struct xsk_ring_prod tx;
	struct xsk_ring_cons rx;
	struct xsk_socket *socket;

	__u32 next_tx_idx;
};

const char *ifname;
static __u8 smac[ETH_ALEN];
static __u8 dmac[ETH_ALEN];
static struct in6_addr saddr;
static struct in6_addr daddr;
static __u16 port;

static void affine(void)
{
	cpu_set_t set;

	if (affinity < 0)
		return;

	printf("affine to core %d\n", affinity);

	CPU_ZERO(&set);
	CPU_SET(affinity++, &set);
	sched_setaffinity(gettid(), sizeof(set), &set);
}

static void fill_tx(struct xsk *xsk, __u32 idx)
{
	struct xsk_tx_metadata *meta;
	struct xdp_desc *tx_desc;
	struct ipv6hdr *ip6h;
	struct udphdr *udph;
	struct ethhdr *eth;
	struct payload *p;
	void *data;
	int ret;
	int len;

	tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, idx);
	tx_desc->addr = idx * UMEM_FRAME_SIZE;
	tx_desc->addr += sizeof(struct xsk_tx_metadata);
	tx_desc->len = ETH_HLEN + sizeof(*ip6h) + sizeof(*udph) + payload_len;
	data = xsk_umem__get_data(xsk->umem_area, tx_desc->addr);

	tx_desc->options |= XDP_TX_METADATA;
	meta = data - sizeof(struct xsk_tx_metadata);
	memset(meta, 0, sizeof(*meta));
	meta->flags = XDP_TXMD_FLAGS_TIMESTAMP;
	if (scheduled_time)
		meta->flags |= XDP_TXMD_FLAGS_SCHEDULE_TIMESTAMP;

	eth = data;
	memcpy(eth->h_dest, dmac, ETH_ALEN);
	memcpy(eth->h_source, smac, ETH_ALEN);
	eth->h_proto = htons(ETH_P_IPV6);

	ip6h = (void *)(eth + 1);
	ip6h->version = 6;
	ip6h->payload_len = htons(sizeof(*udph) + payload_len);
	ip6h->nexthdr = IPPROTO_UDP;
	ip6h->hop_limit = 255;
	ip6h->saddr = saddr;
	ip6h->daddr = daddr;

	udph = (void *)(ip6h + 1);
	udph->source = htons(port);
	udph->dest = htons(port);
	udph->len = ip6h->payload_len;
	if (ignore_csum)
		udph->check = 0;
	else
		udph->check = ~csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr,
					       ntohs(udph->len), IPPROTO_UDP, 0);
}

static int open_xsk(int ifindex, struct xsk *xsk, __u32 queue, int bind_flags)
{
	int mmap_flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE;
	struct xsk_ring_prod *fill = &xsk->fill;
	struct xsk_ring_cons *comp = &xsk->comp;
	struct xsk_ring_prod *tx = &xsk->tx;
	struct xsk_ring_cons *rx = &xsk->rx;
	struct xdp_mmap_offsets off = {};
	struct xdp_umem_reg_copy mr = {};
	struct sockaddr_xdp sxdp = {};
	socklen_t optlen;
	int optval;
	__u64 addr;
	__u32 idx;
	void *map;
	int ret;

	/* allocate socket */

	xsk->fd = socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0);
	if (xsk->fd < 0)
		return -errno;

	/* map umem */

	xsk->umem_area = mmap(NULL, umem_size * UMEM_FRAME_SIZE, PROT_READ | PROT_WRITE, mmap_flags, -1, 0);
	if (xsk->umem_area == MAP_FAILED)
		return -ENOMEM;

	printf("%s chunk addr: %p len: 0x%x\n", __func__, xsk->umem_area, UMEM_FRAME_SIZE);
	mr.addr = (uintptr_t)xsk->umem_area;
	mr.len = umem_size * UMEM_FRAME_SIZE;
	mr.chunk_size = UMEM_FRAME_SIZE;
	mr.headroom = 0;
	mr.flags = 0;
	mr.tx_metadata_len = sizeof(struct xdp_umem_reg_v1);

	if (use_hwtstamp) {
		mr.tx_metadata_len = sizeof(struct xsk_tx_metadata);
		mr.flags = XDP_UMEM_TX_METADATA_LEN;
	}

	ret = setsockopt(xsk->fd, SOL_XDP, XDP_UMEM_REG, &mr, sizeof(mr));
	if (ret)
		return -errno;

	/* allocate fill & completion rings */

	ret = setsockopt(xsk->fd, SOL_XDP, XDP_UMEM_FILL_RING, &ring_size, sizeof(ring_size));
	if (ret)
		return -errno;

	ret = setsockopt(xsk->fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &ring_size, sizeof(ring_size));
	if (ret)
		return -errno;

	/* allocate rx & tx rings */

	ret = setsockopt(xsk->fd, SOL_XDP, XDP_RX_RING, &ring_size, sizeof(ring_size));
	if (ret)
		return -errno;

	ret = setsockopt(xsk->fd, SOL_XDP, XDP_TX_RING, &ring_size, sizeof(ring_size));
	if (ret)
		return -errno;

	/* setup the rings */

	optlen = sizeof(off);
	ret = getsockopt(xsk->fd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen);
	if (ret)
		return -errno;

	map = mmap(NULL, off.fr.desc + ring_size * sizeof(__u64),
		   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
		   xsk->fd,
		   XDP_UMEM_PGOFF_FILL_RING);
	if (map == MAP_FAILED)
		return -errno;

	fill->mask = ring_size - 1;
	fill->size = ring_size;
	fill->producer = map + off.fr.producer;
	fill->consumer = map + off.fr.consumer;
	fill->flags = map + off.fr.flags;
	fill->ring = map + off.fr.desc;
	fill->cached_cons = ring_size;

	map = mmap(NULL, off.cr.desc + ring_size * sizeof(__u64),
		   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
		   xsk->fd,
		   XDP_UMEM_PGOFF_COMPLETION_RING);

	comp->mask = ring_size - 1;
	comp->size = ring_size;
	comp->producer = map + off.cr.producer;
	comp->consumer = map + off.cr.consumer;
	comp->flags = map + off.cr.flags;
	comp->ring = map + off.cr.desc;

	map = mmap(NULL, off.rx.desc +
		   ring_size * sizeof(struct xdp_desc),
		   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
		   xsk->fd,
		   XDP_PGOFF_RX_RING);
	if (map == MAP_FAILED)
		return -errno;

	rx->mask = ring_size - 1;
	rx->size = ring_size;
	rx->producer = map + off.rx.producer;
	rx->consumer = map + off.rx.consumer;
	rx->flags = map + off.rx.flags;
	rx->ring = map + off.rx.desc;
	rx->cached_prod = *rx->producer;
	rx->cached_cons = *rx->consumer;

	map = mmap(NULL, off.tx.desc +
		   ring_size * sizeof(struct xdp_desc),
		   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
		   xsk->fd,
		   XDP_PGOFF_TX_RING);
	if (map == MAP_FAILED)
		return -errno;

	tx->mask = ring_size - 1;
	tx->size = ring_size;
	tx->producer = map + off.tx.producer;
	tx->consumer = map + off.tx.consumer;
	tx->flags = map + off.tx.flags;
	tx->ring = map + off.tx.desc;
	tx->cached_prod = *tx->producer;
	tx->cached_cons = *tx->consumer + ring_size;

	/* First half of umem is for TX. This way address matches 1-to-1
	 * to the completion queue index.
	 */

	for (int i = 0; i < umem_size / 2; i++) {
		addr = i * UMEM_FRAME_SIZE;
		if (debug)
			printf("%p: tx_desc[%d] -> %llx\n", xsk, i, addr);
		if (prefill_headers)
			fill_tx(xsk, i);
	}

	/* Second half of umem is for RX. */

	ret = xsk_ring_prod__reserve(&xsk->fill, umem_size / 2, &idx);
	for (int i = 0; i < umem_size / 2; i++) {
		addr = (umem_size / 2 + i) * UMEM_FRAME_SIZE;
		if (debug)
			printf("%p: rx_desc[%d] -> %llx\n", xsk, i, addr);
		*xsk_ring_prod__fill_addr(&xsk->fill, idx + i) = addr;
	}
	xsk_ring_prod__submit(&xsk->fill, ret);

	/* bind the socket */

	sxdp.sxdp_family = PF_XDP;
	sxdp.sxdp_flags = bind_flags;
	sxdp.sxdp_ifindex = ifindex;
	sxdp.sxdp_queue_id = queue;

	ret = bind(xsk->fd, (struct sockaddr *)&sxdp, sizeof(sxdp));
	if (ret)
		return -errno;

	if (busy_poll) {
		optval = 1;
		if (setsockopt(xsk->fd, SOL_SOCKET, SO_PREFER_BUSY_POLL,
			       &optval, sizeof(optval)) < 0)
			return -errno;

		/* unused, busy-polling mode is always non-blocking */
		optval = 1000; /* usec */
		if (setsockopt(xsk->fd, SOL_SOCKET, SO_BUSY_POLL,
			       &optval, sizeof(optval)) < 0)
			return -errno;

		optval = 8;
		if (setsockopt(xsk->fd, SOL_SOCKET, SO_BUSY_POLL_BUDGET,
			       &optval, sizeof(optval)) < 0)
			return -errno;
	}

	return 0;
}

static void *packet_payload(struct xsk *xsk, __u32 idx)
{
	struct xdp_desc *tx_desc;

	tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, xsk->next_tx_idx);
	return xsk_umem__get_data(xsk->umem_area, tx_desc->addr);
}

static void csum_tx(struct xsk *xsk, __u32 idx)
{
	struct xsk_tx_metadata *meta;
	struct ipv6hdr *ip6h;
	struct udphdr *udph;
	struct ethhdr *eth;
	void *data;

	data = packet_payload(xsk, idx);

	if (offload_tx_csum) {
		meta = data - sizeof(struct xsk_tx_metadata);
		meta = data - sizeof(struct xsk_tx_metadata);
		meta->flags |= XDP_TXMD_FLAGS_CHECKSUM;
		meta->request.csum_start = sizeof(*eth) + sizeof(*ip6h);
		meta->request.csum_offset = offsetof(struct udphdr, check);
		return;
	}

	eth = data;
	ip6h = (void *)(eth + 1);
	udph = (void *)(ip6h + 1);

	if (prefill_headers)
		udph->check = ~csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr,
					       ntohs(udph->len), IPPROTO_UDP, 0);

	udph->check = csum_fold(csum_partial(udph, sizeof(*udph) + payload_len, 0));
}

static void prepare_tx(struct xsk *xsk, __u32 id, __u32 type, __u64 tstamp)
{
	struct ipv6hdr *ip6h;
	struct udphdr *udph;
	struct ethhdr *eth;
	struct payload *p;

	if (!prefill_headers)
		fill_tx(xsk, xsk->next_tx_idx);

	eth = packet_payload(xsk, xsk->next_tx_idx);
	ip6h = (void *)(eth + 1);
	udph = (void *)(ip6h + 1);
	p = (void *)(udph + 1);

	p->id = id;
	p->type = type;
	p->tstamp = tstamp;
	p->xdp_hw_tstamp = 0;
	p->xdp_sw_tstamp = 0;

	if (!ignore_csum)
		csum_tx(xsk, xsk->next_tx_idx);
}

static void close_xsk(struct xsk *xsk)
{
	munmap(xsk->umem_area, umem_size * UMEM_FRAME_SIZE);
	close(xsk->fd);
}

static void kick_tx(struct xsk *xsk)
{
	if (threaded_poll)
		return;

	if (use_need_wakeup && !xsk_ring_prod__needs_wakeup(&xsk->tx))
		return;

	if (sendto(xsk->fd, NULL, 0, MSG_DONTWAIT, NULL, 0) < 0)
		error(1, errno, "kick_tx");
}

static void kick_rx(struct xsk *xsk)
{
	if (threaded_poll)
		return;

	if (recvfrom(xsk->fd, NULL, 0, MSG_DONTWAIT, NULL, NULL) < 0)
		error(1, errno, "kick_rx");
}
static void submit_tx(struct xsk *xsk)
{
	__u32 idx = 0;
	__u32 got;

	got = xsk_ring_prod__reserve(&xsk->tx, 1, &idx);
	if (got != 1)
		error(1, EINVAL, "xsk_ring_prod__reserve");
	if (debug)
		printf("submit_idx idx=%u\n", idx);

	if (idx != xsk->next_tx_idx)
		error(1, EINVAL, "unexpected tx id");

	xsk_ring_prod__submit(&xsk->tx, got);
	xsk->next_tx_idx = (xsk->next_tx_idx + 1) % (umem_size / 2);

	kick_tx(xsk);
}

static __u64 wait_complete_tx(struct xsk *xsk, __u64 *scheduled)
{
	struct xsk_tx_metadata *meta;
	__u32 idx = 0;
	int complete;
	__u64 addr;
	void *data;

	do {
		complete = xsk_ring_cons__peek(&xsk->comp, 1, &idx);
		if (debug)
			printf("complete_tx idx=%u\n", idx);
		if (complete != 1 && busy_poll)
			kick_tx(xsk);
	} while (complete != 1);

	addr = *xsk_ring_cons__comp_addr(&xsk->comp, idx);
	data = xsk_umem__get_data(xsk->umem_area, addr);
	meta = data - sizeof(struct xsk_tx_metadata);

	xsk_ring_cons__release(&xsk->comp, 1);
	if (scheduled)
		*scheduled = meta->completion.tx_schedule_timestamp;

	return meta->completion.tx_timestamp;
}

static void refill_rx(struct xsk *xsk, __u64 addr)
{
	__u32 idx;

	xsk_ring_cons__release(&xsk->rx, 1);

	if (xsk_ring_prod__reserve(&xsk->fill, 1, &idx) == 1) {
		*xsk_ring_prod__fill_addr(&xsk->fill, idx) = addr;
		xsk_ring_prod__submit(&xsk->fill, 1);
	}
}

static struct payload *wait_rx(struct xsk *xsk, __u64 *comp_addr)
{
	const struct xdp_desc *rx_desc;
	struct ipv6hdr *ip6h;
	struct udphdr *udph;
	struct ethhdr *eth;
	__u32 idx = 0;
	__u64 addr;
	__u32 got;

	while (true) {
		got = xsk_ring_cons__peek(&xsk->rx, 1, &idx);
		if (!got) {
			kick_rx(xsk);
			continue;
		}

		rx_desc = xsk_ring_cons__rx_desc(&xsk->rx, idx);
		*comp_addr = xsk_umem__extract_addr(rx_desc->addr);
		addr = xsk_umem__add_offset_to_addr(rx_desc->addr);

		eth = xsk_umem__get_data(xsk->umem_area, addr);
		ip6h = (void *)(eth + 1);
		udph = (void *)(ip6h + 1);

		if (eth->h_proto != htons(ETH_P_IPV6))
			error(1, EINVAL, "Unexpected eth packet proto 0x%x (expected 0x%x)", eth->h_proto, htons(ETH_P_IPV6));

		if (ip6h->nexthdr != IPPROTO_UDP)
			error(1, EINVAL, "Unexpected IP packet proto 0x%x (expected 0x%x)", ip6h->nexthdr, IPPROTO_UDP);

		return (void *)(udph + 1);
	}

	return NULL;
}

struct probe {
	__u64 tx_sw;
	__u64 rx_sw_xdp;
	__u64 rx_sw;

	__u64 tx_scheduled; /* CLOCK_TAI - needs custom patches */
	__u64 tx_hw; /* client reply tx timestamp */
	__u64 rx_hw; /* client request rx timestamp */

	__u64 peer_rx_hw;
	__u64 peer_tx_hw;
	__u64 peer_xsk;
};

static __u64 now(void)
{
	struct timespec ts = {};

	clock_gettime(CLOCK_TAI, &ts);
	return ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
}

static const char *hw_rtt_info = "(request_hw_tx_timestamp - reply_hw_rx_timestamp)";
static const char *sw_time_info = "(SW_RTT - HW_RTT)";
static const char *peer_time_info = "(peer reply_hw_tx_timestamp - peer request_hw_rx_timestamp)";
static const char *fabric_rtt_info = "(HW_RTT - PEER_TIME)";
static const char *peer_drv_time_info = "(PEER_TIME - PEER_XSK_TIME, includes HW RX and TX delays)";

static void dump_probe(struct probe *probe)
{
	__u64 sw_rtt, hw_rtt, fabric_rtt, peer_time, xdp2xsk;
	__u64 peer_drv_time;
	__u64 xsk2dev = 0;

	sw_rtt = probe->rx_sw - probe->tx_sw;
	hw_rtt = probe->rx_hw - probe->tx_hw;
	xdp2xsk = probe->rx_sw - probe->rx_sw_xdp;
	peer_time = probe->peer_tx_hw - probe->peer_rx_hw;
	fabric_rtt = hw_rtt - peer_time;
	peer_drv_time = peer_time - probe->peer_xsk;
	if (scheduled_time)
		xsk2dev = probe->tx_scheduled - probe->tx_sw;

	if (plain) {
		printf("SW_RTT %lluns\n", sw_rtt);
		printf("HW_RTT %lluns %s\n", hw_rtt, hw_rtt_info);
		printf("SW_TIME %lluns %s\n", sw_rtt - hw_rtt, sw_time_info);
		printf("PEER_TIME %lluns %s\n", peer_time, peer_time_info);
		printf("FABIC_RTT %lluns %s\n", hw_rtt - peer_time, fabric_rtt_info);
		printf("PEER_XSK_TIME %lluns\n", probe->peer_xsk);
		printf("PEER_DRV_TIME %lluns %s\n", peer_drv_time, peer_drv_time_info);
		printf("RX_XDP_TO_XSK %lluns\n", xdp2xsk);
		if (scheduled_time)
			printf("TX_XSK_TO_DEV %lluns\n", xsk2dev);
		printf("\n");
		return;
	}

	printf("PEER_XSK_TIME:             |-------|             %llu\n", probe->peer_xsk);
	printf("HW_TIME:               |-|           |-|         ?\n");
	printf("PEER_DRV_TIME:         |---|       |---|         %llu %s\n", peer_drv_time, peer_drv_time_info);
	printf("PEER_TIME:             |---------------|         %llu %s\n", peer_time, peer_time_info);
	/*                             ^ peer_rx_hw (request_hw_rx_timestamp) */
	/*                                             ^ peer_tx_hw (reply_hw_tx_timestamp) */
	printf("FABRIC_RTT:         |--|               |--|      %llu %s\n", fabric_rtt, fabric_rtt_info);
	printf("HW_RTT:             |---------------------|      %llu %s\n", hw_rtt, hw_rtt_info);
	/*                          ^ tx_hw (request_hw_tx_timestamp) */
	/*                                                ^ rx_hw (reply_hw_rx_timestamp) */
	printf("SW_RTT:         |-----------------------------|  %llu\n", sw_rtt);
	/*                      ^ tx_sw */
	/*                                                    ^ rx_sw */
	printf("HW_TIME:          |-|                     |-|    ? (<<%llu)\n", sw_rtt - hw_rtt - xdp2xsk - xsk2dev);
	printf("SW_TIME:        |-|                         |-|  %llu %s\n", sw_rtt - hw_rtt, sw_time_info);
	printf("                ^ TX_XSK_TO_DEV             ^ RX_XDP_TO_XSK\n");
	printf("               %7llu                      %llu\n", xsk2dev, xdp2xsk);
	printf("\n");



}

static void server(struct xsk *xsk, int queue)
{
	const struct xdp_desc *rx_desc;
	struct sockaddr_in6 sin6;
	__u64 comp_addr, addr;
	struct payload *p;
	__u64 begin, end;
	__u64 tx_hw;
	__u32 idx;
	int ret;
	int got;

	while (true) {
		p = wait_rx(xsk, &comp_addr);
		begin = now();
		if (!p)
			error(1, -errno, "TYPE_RQ NULL");
		if (p->type != TYPE_RQ)
			error(1, -errno, "TYPE_RQ");

		prepare_tx(xsk, p->id, TYPE_RX, p->xdp_hw_tstamp);
		submit_tx(xsk);
		end = now();
		tx_hw = wait_complete_tx(xsk, NULL);

		prepare_tx(xsk, p->id, TYPE_TX, tx_hw);
		submit_tx(xsk);
		(void)wait_complete_tx(xsk, NULL);

		prepare_tx(xsk, p->id, TYPE_USER, end - begin);
		submit_tx(xsk);
		(void)wait_complete_tx(xsk, NULL);

		refill_rx(xsk, comp_addr);
		printf("AF_XDP RX_TX SW=%lluns\n", end - begin);
	}
}

static int interruped(struct xsk *xsk, int timeo_ms)
{
	struct pollfd fds[1];
	int ret;

	fds[0].fd = STDIN_FILENO;
	fds[0].events = POLLIN;
	fds[0].revents = 0;

	ret = poll(fds, 1, timeo_ms);
	if (ret < 0)
		return 0;

	if (fds[0].revents)
		return 1;

	return 0;
}

static void client(struct xsk *xsk)
{
	__u32 id = 0xcafecafe;
	struct probe probe;
	struct payload *p;
	__u64 comp_addr;
	int sent = -1;
	int ret;

	while (!interruped(xsk, 1000)) {
		prepare_tx(xsk, id, TYPE_RQ, 0);
		probe.tx_sw = now();
		submit_tx(xsk);

		p = wait_rx(xsk, &comp_addr);
		if (!p)
			error(1, -errno, "TYPE_RX NULL");
		if (p->type != TYPE_RX)
			error(1, -errno, "TYPE_RX");
		if (p->id != id)
			error(1, -errno, "TYPE_RX id");

		probe.rx_sw = now();
		probe.rx_hw = p->xdp_hw_tstamp;
		probe.rx_sw_xdp = p->xdp_sw_tstamp;
		probe.peer_rx_hw = p->tstamp;
		refill_rx(xsk, comp_addr);

		p = wait_rx(xsk, &comp_addr);
		if (!p)
			error(1, -errno, "TYPE_TX NULL");
		if (p->type != TYPE_TX)
			error(1, -errno, "TYPE_TX");
		if (p->id != id)
			error(1, -errno, "TYPE_TX id");

		probe.peer_tx_hw = p->tstamp;

		p = wait_rx(xsk, &comp_addr);
		if (!p)
			error(1, -errno, "TYPE_USER NULL");
		if (p->type != TYPE_USER)
			error(1, -errno, "TYPE_USER");
		if (p->id != id)
			error(1, -errno, "TYPE_USER id");

		probe.peer_xsk = p->tstamp;
		probe.tx_hw = wait_complete_tx(xsk, &probe.tx_scheduled);
		refill_rx(xsk, comp_addr);

		dump_probe(&probe);
		id++;
	}
}

static void hwtstamp_ioctl(int op, const char *ifname, struct hwtstamp_config *cfg)
{
	struct ifreq ifr = {
		.ifr_data = (void *)cfg,
	};
	int fd, ret;

	strncpy(ifr.ifr_name, ifname, IF_NAMESIZE - 1);

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0)
		error(1, errno, "socket");

	ret = ioctl(fd, op, &ifr);
	if (ret < 0)
		error(1, errno, "ioctl(%d)", op);

	close(fd);
}

static void hwtstamp_enable(const char *ifname)
{
	struct hwtstamp_config cfg = {
		.rx_filter = HWTSTAMP_FILTER_ALL,
		.tx_type = HWTSTAMP_TX_ON,
	};

	hwtstamp_ioctl(SIOCSHWTSTAMP, ifname, &cfg);
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [OPTS] [-c] <ifname> <src mac> <dst mac> <src ip> <dst ip> <src/dst port> <queue_idx>\n"
		"OPTS:\n"
		"    -c    run as client\n"
		"    -C    offload L3 csum to the NIC\n"
		"    -d    debug mode: single packet, sleep between them\n"
		"    -p    prefer busy poll\n"
		"    -R    number of entries in fill/comp/rx/tx rings (per ring)\n"
		"    -s    packet payload size (1400 is default)\n"
		"    -w    set XDP_USE_NEED_WAKEUP\n"
		"",
		prog);
}

#define swap(a, b, len) do { \
	for (int i = 0; i < len; i++) { \
		__u8 tmp = ((__u8 *)a)[i]; \
		((__u8 *)a)[i] = ((__u8 *)b)[i]; \
		((__u8 *)b)[i] = tmp; \
	} \
} while (0)

static int ethtool(const char *ifname, void *data)
{
	struct ifreq ifr = {};
	int ret;

	strcat(ifr.ifr_ifrn.ifrn_name, ifname);
	ifr.ifr_ifru.ifru_data = data;

	int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0)
		return fd;

	ret = ioctl(fd, SIOCETHTOOL, &ifr);
	close(fd);
	return ret;
}

static void reset_flow_steering(const char *ifname)
{
	struct ethtool_rxnfc cnt = {};
	struct ethtool_rxnfc *rules;

	cnt.cmd = ETHTOOL_GRXCLSRLCNT;
	if (ethtool(ifname, &cnt) < 0)
		return;

	rules = calloc(1, sizeof(*rules) + (cnt.rule_cnt * sizeof(__u32)));
	if (!rules)
		return;

	rules->cmd = ETHTOOL_GRXCLSRLALL;
	rules->rule_cnt = cnt.rule_cnt;
	if (ethtool(ifname, rules) < 0)
		goto free_rules;

	for (__u32 i = 0; i < rules->rule_cnt; i++) {
		struct ethtool_rxnfc del;

		del.cmd = ETHTOOL_SRXCLSRLDEL;
		del.fs.location = rules->rule_locs[i];

		ethtool(ifname, &del);
	}

free_rules:
	free(rules);
}

static int add_steering_rule(struct in6_addr *addr, int port,
			     const char *ifname, int queue, int idx)
{
	struct ethtool_rxnfc add = {};

	add.cmd = ETHTOOL_SRXCLSRLINS;
	add.fs.location = idx;
	add.fs.ring_cookie = queue;
	add.fs.flow_type = UDP_V6_FLOW;
	memcpy(add.fs.h_u.tcp_ip6_spec.ip6dst, addr, 16);
	add.fs.h_u.tcp_ip6_spec.pdst = htons(port);
	add.fs.m_u.tcp_ip6_spec.ip6dst[0] = 0xffffffff;
	add.fs.m_u.tcp_ip6_spec.ip6dst[1] = 0xffffffff;
	add.fs.m_u.tcp_ip6_spec.ip6dst[2] = 0xffffffff;
	add.fs.m_u.tcp_ip6_spec.ip6dst[3] = 0xffffffff;
	add.fs.m_u.tcp_ip6_spec.pdst = 0xffff;

	return ethtool(ifname, &add);
}

static int rss_equal(const char *ifname, int max_queue)
{
	struct ethtool_rxfh_indir get = {};
	struct ethtool_rxfh_indir *set;
	int queue = 0;
	int ret;

	get.cmd = ETHTOOL_GRXFHINDIR;
	if (ethtool(ifname, &get) < 0)
		return -1;

	set = malloc(sizeof(*set) + get.size * sizeof(__u32));
	if (!set)
		return -1;

	for (__u32 i = 0; i < get.size; i++) {
		set->ring_index[i] = queue++;
		if (queue >= max_queue)
			queue = 0;
	}

	set->cmd = ETHTOOL_SRXFHINDIR;
	set->size = get.size;
	ret = ethtool(ifname, set);

	free(set);
	return ret;
}

static void *do_busy_poll(void *arg)
{
	int *fd = arg;

	printf("started polling thread\n");
	affine();

	while (true) {
		if (recvfrom(*fd, NULL, 0, MSG_DONTWAIT, NULL, NULL) < 0)
			error(1, errno, "recvfrom");
	}
}

int main(int argc, char *argv[])
{
	int bind_flags =  XDP_ZEROCOPY;
	int ifindex, val, opt, ret;
	struct bpf_program *prog;
	bool is_server = true;
	struct xsk xsk = {};
	struct xskrtt *obj;
	pthread_t thread;
	__u32 key;
	int queue;

	while ((opt = getopt(argc, argv, "a:cCdfipPR:s:Stwh")) != -1) {
		switch (opt) {
		case 'a':
			affinity = atoi(optarg);
			break;
		case 'c':
			is_server = false;
			break;
		case 'C':
			offload_tx_csum = true;
			break;
		case 'd':
			debug = true;
			break;
		case 'f':
			prefill_headers = true;
			break;
		case 'i':
			ignore_csum = true;
			break;
		case 'p':
			busy_poll = true;
			break;
		case 'P':
			plain = true;
			break;
		case 'R':
			ring_size = atoi(optarg);
			assert(ring_size > 0 & ring_size % 8 == 0);
			break;
		case 's':
			payload_len = atoll(optarg);
			assert(payload_len < 4096 - 256);
			break;
		case 'S':
			scheduled_time = true;
			break;
		case 't':
			threaded_poll = true;
			break;
		case 'w':
			use_need_wakeup = true;
			break;
		case 'h':
			use_hwtstamp = false;
		default:
			usage(basename(argv[0]));
			return 1;
		}
	}
	assert(payload_len >= sizeof(struct payload));

	if (use_need_wakeup)
		bind_flags |= XDP_USE_NEED_WAKEUP;

	if (threaded_poll && !busy_poll)
		error(1, EINVAL, "threaded mode requires busy poll");

	if (argc < 1 + 7 || optind >= argc) {
		usage(basename(argv[0]));
		return -1;
	}

	ifname = argv[optind];
	ifindex = if_nametoindex(ifname);

	sscanf(argv[optind + 1], "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX",
	       &smac[0], &smac[1], &smac[2], &smac[3], &smac[4], &smac[5]);
	sscanf(argv[optind + 2], "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX",
	       &dmac[0], &dmac[1], &dmac[2], &dmac[3], &dmac[4], &dmac[5]);

	inet_pton(AF_INET6, argv[optind + 3], &saddr);
	inet_pton(AF_INET6, argv[optind + 4], &daddr);

	port = atoi(argv[optind + 5]);
	queue = atoi(argv[optind + 6]);

	if (use_hwtstamp)
		hwtstamp_enable(ifname);

	printf("open_xsk:");
	printf(" ifname=%s", ifname);
	printf(" ifindex=%d", ifindex);
	printf(" port=%d", port);
	printf(" queue=%d", queue);
	printf(" bind_flags=%x", bind_flags);
	printf(" ring_size=%d", ring_size);
	printf(" umem_size=%d", umem_size);
	printf("\n");

	if (use_flowsteering)
		reset_flow_steering(ifname);

	if (use_flowsteering) {
		ret = rss_equal(ifname, queue);
		if (ret)
			error(1, -ret, "rss_equal");

		ret = add_steering_rule(&saddr, port, ifname, queue, 1);
		if (ret)
			error(1, -ret, "add_steering_rule");
	}

	ret = open_xsk(ifindex, &xsk, queue, bind_flags);
	if (ret)
		error(1, -ret, "open_xsk");

	printf("xsk->fd=%d\n", xsk.fd);

	key = 0;
	val = xsk.fd;

	printf("open bpf program...\n");
	obj = xskrtt__open();
	if (libbpf_get_error(obj))
		error(1, libbpf_get_error(obj), "xskrtt__open");

	prog = bpf_object__find_program_by_name(obj->obj, "rx");
	bpf_program__set_ifindex(prog, ifindex);
	bpf_program__set_flags(prog, BPF_F_XDP_DEV_BOUND_ONLY);

	printf("load bpf program...\n");
	ret = xskrtt__load(obj);
	if (ret < 0)
		error(1, -ret, "xskrtt__load");

	printf("setup bpf program...\n");
	obj->bss->port = port;
	ret = bpf_map_update_elem(bpf_map__fd(obj->maps.xsk), &key, &val, 0);
	if (ret)
		error(1, -ret, "bpf_map_update_elem");

	printf("attach bpf program...\n");
	ret = bpf_xdp_attach(ifindex,
			     bpf_program__fd(obj->progs.rx),
			     XDP_FLAGS, NULL);
	if (ret)
		error(1, -ret, "bpf_xdp_attach");

	affine();
	if (threaded_poll) {
		ret = pthread_create(&thread, NULL, do_busy_poll, &xsk.fd);
		if (ret)
			error(1, errno, "pthread_create");
	}

	if (is_server) {
		printf("serving requests on port %d\n", port);
		server(&xsk, queue);
	} else {
		printf("sending to repote port %d\n", port);
		client(&xsk);
	}

	close_xsk(&xsk);
}
