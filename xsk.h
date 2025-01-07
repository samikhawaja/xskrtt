/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * AF_XDP user-space access library.
 *
 * Copyright (c) 2018 - 2019 Intel Corporation.
 * Copyright (c) 2019 Facebook
 *
 * Author(s): Magnus Karlsson <magnus.karlsson@intel.com>
 */

#pragma once

#include <linux/if_xdp.h>
#include <bpf/libbpf.h>

#define DEFINE_XSK_RING(name) \
struct name { \
	__u32 cached_prod; \
	__u32 cached_cons; \
	__u32 mask; \
	__u32 size; \
	__u32 *producer; \
	__u32 *consumer; \
	void *ring; \
	__u32 *flags; \
}

DEFINE_XSK_RING(xsk_ring_prod);
DEFINE_XSK_RING(xsk_ring_cons);

static inline int xsk_ring_prod__needs_wakeup(const struct xsk_ring_prod *r)
{
    return *r->flags & XDP_RING_NEED_WAKEUP;
}

static inline __u64 xsk_umem__extract_addr(__u64 addr)
{
	return addr & XSK_UNALIGNED_BUF_ADDR_MASK;
}

static inline __u64 xsk_umem__extract_offset(__u64 addr)
{
	return addr >> XSK_UNALIGNED_BUF_OFFSET_SHIFT;
}

static inline __u64 xsk_umem__add_offset_to_addr(__u64 addr)
{
	return xsk_umem__extract_addr(addr) + xsk_umem__extract_offset(addr);
}

static inline __u64 *xsk_ring_prod__fill_addr(struct xsk_ring_prod *fill,
					      __u32 idx)
{
	__u64 *addrs = (__u64 *)fill->ring;

	return &addrs[idx & fill->mask];
}

static inline const __u64 *
xsk_ring_cons__comp_addr(const struct xsk_ring_cons *comp, __u32 idx)
{
	const __u64 *addrs = (const __u64 *)comp->ring;

	return &addrs[idx & comp->mask];
}

static inline struct xdp_desc *xsk_ring_prod__tx_desc(struct xsk_ring_prod *tx,
						      __u32 idx)
{
	struct xdp_desc *descs = (struct xdp_desc *)tx->ring;

	return &descs[idx & tx->mask];
}

static inline const struct xdp_desc *
xsk_ring_cons__rx_desc(const struct xsk_ring_cons *rx, __u32 idx)
{
	const struct xdp_desc *descs = (const struct xdp_desc *)rx->ring;

	return &descs[idx & rx->mask];
}

static inline __u32 xsk_prod_nb_free(struct xsk_ring_prod *r, __u32 nb)
{
	__u32 free_entries = r->cached_cons - r->cached_prod;

	if (free_entries >= nb)
		return free_entries;

	/* Refresh the local tail pointer.
	 * cached_cons is r->size bigger than the real consumer pointer so
	 * that this addition can be avoided in the more frequently
	 * executed code that computs free_entries in the beginning of
	 * this function. Without this optimization it whould have been
	 * free_entries = r->cached_prod - r->cached_cons + r->size.
	 */
	r->cached_cons = __atomic_load_n(r->consumer, __ATOMIC_ACQUIRE);
	r->cached_cons += r->size;

	return r->cached_cons - r->cached_prod;
}

static inline __u32 xsk_cons_nb_avail(struct xsk_ring_cons *r, __u32 nb)
{
	__u32 entries = r->cached_prod - r->cached_cons;

	if (entries == 0) {
		r->cached_prod = __atomic_load_n(r->producer, __ATOMIC_ACQUIRE);
		entries = r->cached_prod - r->cached_cons;
	}

	return (entries > nb) ? nb : entries;
}

static inline __u32 xsk_ring_prod__reserve(struct xsk_ring_prod *prod, __u32 nb, __u32 *idx)
{
	if (xsk_prod_nb_free(prod, nb) < nb)
		return 0;

	*idx = prod->cached_prod;
	prod->cached_prod += nb;

	return nb;
}

static inline void xsk_ring_prod__submit(struct xsk_ring_prod *prod, __u32 nb)
{
	/* Make sure everything has been written to the ring before indicating
	 * this to the kernel by writing the producer pointer.
	 */
	__atomic_store_n(prod->producer, *prod->producer + nb, __ATOMIC_RELEASE);
}

static inline __u32 xsk_ring_cons__peek(struct xsk_ring_cons *cons, __u32 nb, __u32 *idx)
{
	__u32 entries = xsk_cons_nb_avail(cons, nb);

	if (entries > 0) {
		*idx = cons->cached_cons;
		cons->cached_cons += entries;
	}

	return entries;
}

static inline void xsk_ring_cons__release(struct xsk_ring_cons *cons, __u32 nb)
{
	/* Make sure data has been read before indicating we are done
	 * with the entries by updating the consumer pointer.
	 */
	__atomic_store_n(cons->consumer, *cons->consumer + nb, __ATOMIC_RELEASE);
}

static inline void *xsk_umem__get_data(void *umem_area, __u64 addr)
{
	return &((char *)umem_area)[addr];
}

