# xskrtt

Estimate fabric RTT with AF_XDP and hardware RX/TX timestamps.

Server waits for the incoming message and replies with two messages back:
1. First packet contains HW RX timestamp of the initial request message
2. Second packet contains HW TX timestamp of the first message

Client sends the request and collects two replies. Client also collects HW TX
timestamp of its request and HW RX timestamp of the first reply. There
is enough info to estimate various parts of the delay:

```
[client] SW_TX_TSTAMP -> HW_TX_TSTAMP -> FABRIC -> [server] HW_RX_TSTAMP_PEER -> HW_TX_TSTAMP_PEER -> FABRIC -> [client] HW_RX_TSTAMP -> SW_RX_TSTAMP
```

HW and SW timestamps are in different time domains and can't be compared,
but it's easy to calculate the following:

- SW_RTT: SW_RX_TSTAMP - SW_TX_TSTAMP
- HW_RTT: HW_RX_TSTAMP - HW_TX_TSTAMP
- PEER_SW_TIME: HW_TX_TSTAMP_PEER - HW_RX_TSTAMP_PEER
- FABIRIC_RTT: HW_RTT - PEER_SW_TIME

Additionally, RX_XDP_TO_XSK is also calculated as the difference between
the time (CLOCK_TAI) when we receive the packet on the AF_XDP userspace
side and the time when the XDP program receives the packet (via
bpf_ktime_get_tai_ns). For a busy-polling case, this basically covers
`recvmsg->__xsk_recvmsg->sk_busy_loop` path.

With a custom kernel patch it's possible to estimate the time it
takes the XSK frame to traverse the stack (TX_XSK_TO_DEV).

Busy-polling requires the following setup on both sides:

```
echo 2 > /sys/class/net/$DEV/napi_defer_hard_irqs
echo 2000000 > /sys/class/net/$DEV/gro_flush_timeout
```
