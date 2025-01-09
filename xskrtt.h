#pragma once

/* Initial request, tstamp is 0 (ignored). */
#define TYPE_RQ 1
/* First reply, tstamp carries RX HW timestamp of the peer. */
#define TYPE_RX 2
/* Second reply, tstamp carries TX HW timestamp of the first reply. */
#define TYPE_TX 3
/* Third reply, tstamp carries userspace time that took to receive and transmit the first reply. */
#define TYPE_USER 4

struct payload {
	__u32 id;
	__u32 type;
	__u64 tstamp;
	/* HW RX timestamp from XDP metadata */
	__u64 xdp_hw_tstamp;
	/* SW RX timestamp from bpf_ktime_get_ns (CLOCK_MONOTONIC) */
	__u64 xdp_sw_tstamp;
};
