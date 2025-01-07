/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#pragma once

#ifndef XDP_TX_METADATA
#define XDP_TX_METADATA				        (1 << 1)

#define XDP_TXMD_FLAGS_TIMESTAMP		    (1 << 0)
#define XDP_TXMD_FLAGS_CHECKSUM			    (1 << 1)
/* Needs custom patches */
#define XDP_TXMD_FLAGS_SCHEDULE_TIMESTAMP	(1 << 2)

struct xsk_tx_metadata {
	__u64 flags;

	union {
		struct {
			/* XDP_TXMD_FLAGS_CHECKSUM */

			/* Offset from desc->addr where checksumming should start. */
			__u16 csum_start;
			/* Offset from csum_start where checksum should be stored. */
			__u16 csum_offset;
		} request;

		struct {
			/* XDP_TXMD_FLAGS_TIMESTAMP */
			__u64 tx_timestamp;
			/* XDP_TXMD_FLAGS_SCHEDULE_TIMESTAMP */
			__u64 tx_schedule_timestamp;
		} completion;
	};
};

struct xdp_umem_reg_copy {
	__u64 addr;
	__u64 len;
	__u32 chunk_size;
	__u32 headroom;
	__u32 flags;
	__u32 tx_metadata_len;
};
#endif
